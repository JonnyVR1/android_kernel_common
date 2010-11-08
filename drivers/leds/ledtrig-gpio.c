/*
 * ledtrig-gio.c - LED Trigger Based on GPIO events
 *
 * Copyright 2009 Felipe Balbi <me@felipebalbi.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/leds.h>
#include <linux/slab.h>
#include <linux/list.h>
#include "leds.h"

static DEFINE_MUTEX(gpio_trig_list_lock);
static LIST_HEAD(gpio_trig_list);

struct gpio_trig_data {
	struct led_classdev *led;
	struct work_struct work;
	struct list_head list;
	struct mutex lock;
	bool active;

	unsigned desired_brightness;	/* desired brightness when led is on */
	unsigned inverted;		/* true when gpio is inverted */
	unsigned gpio;			/* gpio that triggers the leds */
};

static struct gpio_trig_data *gpio_trig_get_data(struct led_classdev *led)
{
	struct gpio_trig_data *gpio_data;

	mutex_lock(&gpio_trig_list_lock);
	list_for_each_entry(gpio_data, &gpio_trig_list, list) {
		if (gpio_data->led == led) {
			mutex_unlock(&gpio_trig_list_lock);
			return gpio_data;
		}
	}

	mutex_unlock(&gpio_trig_list_lock);
	return NULL;
}

static irqreturn_t gpio_trig_irq(int irq, void *_led)
{
	struct led_classdev *led = _led;
	struct gpio_trig_data *gpio_data = led->trigger_data;

	/* just schedule_work since gpio_get_value can sleep */
	schedule_work(&gpio_data->work);

	return IRQ_HANDLED;
};

static void gpio_trig_work(struct work_struct *work)
{
	struct gpio_trig_data *gpio_data = container_of(work,
			struct gpio_trig_data, work);
	int tmp;

	if (!gpio_data->gpio)
		return;

	tmp = gpio_get_value(gpio_data->gpio);
	if (gpio_data->inverted)
		tmp = !tmp;

	if (tmp) {
		if (gpio_data->desired_brightness)
			led_set_brightness(gpio_data->led,
					   gpio_data->desired_brightness);
		else
			led_set_brightness(gpio_data->led, LED_FULL);
	} else {
		led_set_brightness(gpio_data->led, LED_OFF);
	}
}

static ssize_t gpio_trig_brightness_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct led_classdev *led = dev_get_drvdata(dev);
	struct gpio_trig_data *gpio_data;

	gpio_data = gpio_trig_get_data(led);
	if (!gpio_data)
		return -EINVAL;

	return sprintf(buf, "%u\n", gpio_data->desired_brightness);
}

static ssize_t gpio_trig_brightness_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct led_classdev *led = dev_get_drvdata(dev);
	struct gpio_trig_data *gpio_data;
	unsigned desired_brightness;
	int ret;

	gpio_data = gpio_trig_get_data(led);
	if (!gpio_data)
		return -EINVAL;

	ret = sscanf(buf, "%u", &desired_brightness);
	if (ret < 1 || desired_brightness > 255) {
		dev_err(dev, "invalid value\n");
		return -EINVAL;
	}

	mutex_lock(&gpio_data->lock);
	gpio_data->desired_brightness = desired_brightness;

	if (gpio_data->active)
		schedule_work(&gpio_data->work);
	mutex_unlock(&gpio_data->lock);

	return n;
}
static DEVICE_ATTR(desired_brightness, 0644, gpio_trig_brightness_show,
		gpio_trig_brightness_store);

static ssize_t gpio_trig_inverted_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct led_classdev *led = dev_get_drvdata(dev);
	struct gpio_trig_data *gpio_data;

	gpio_data = gpio_trig_get_data(led);
	if (!gpio_data)
		return -EINVAL;

	return sprintf(buf, "%s\n", gpio_data->inverted ? "yes" : "no");
}

static ssize_t gpio_trig_inverted_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct led_classdev *led = dev_get_drvdata(dev);
	struct gpio_trig_data *gpio_data;
	unsigned inverted;
	int ret;

	gpio_data = gpio_trig_get_data(led);
	if (!gpio_data)
		return -EINVAL;

	ret = sscanf(buf, "%u", &inverted);
	if (ret < 1) {
		dev_err(dev, "invalid value\n");
		return -EINVAL;
	}

	mutex_lock(&gpio_data->lock);
	gpio_data->inverted = !!inverted;

	/* After inverting, we need to update the LED. */
	if (gpio_data->active)
		schedule_work(&gpio_data->work);
	mutex_unlock(&gpio_data->lock);

	return n;
}
static DEVICE_ATTR(inverted, 0644, gpio_trig_inverted_show,
		gpio_trig_inverted_store);

static ssize_t gpio_trig_gpio_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct led_classdev *led = dev_get_drvdata(dev);
	struct gpio_trig_data *gpio_data;

	gpio_data = gpio_trig_get_data(led);
	if (!gpio_data)
		return -EINVAL;

	return sprintf(buf, "%u\n", gpio_data->gpio);
}

static ssize_t gpio_trig_gpio_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t n)
{
	struct led_classdev *led = dev_get_drvdata(dev);
	struct gpio_trig_data *gpio_data;
	unsigned gpio;
	int ret = 0;

	gpio_data = gpio_trig_get_data(led);
	if (!gpio_data)
		return -EINVAL;

	ret = sscanf(buf, "%u", &gpio);
	if (ret < 1) {
		dev_err(dev, "couldn't read gpio number\n");
		return -EINVAL;
	}

	mutex_lock(&gpio_data->lock);

	if (gpio_data->gpio == gpio)
		goto out;

	if (!gpio) {
		if (gpio_data->gpio != 0)
			free_irq(gpio_to_irq(gpio_data->gpio), led);
		gpio_data->gpio = 0;
		goto out;
	}

	ret = request_irq(gpio_to_irq(gpio), gpio_trig_irq,
			IRQF_SHARED | IRQF_TRIGGER_RISING
			| IRQF_TRIGGER_FALLING, "ledtrig-gpio", led);
	if (ret) {
		dev_err(dev, "request_irq failed with error %d\n", ret);
	} else {
		if (gpio_data->gpio != 0)
			free_irq(gpio_to_irq(gpio_data->gpio), led);
		gpio_data->gpio = gpio;
		if (!gpio_data->active)
			disable_irq(gpio_to_irq(gpio_data->gpio));
	}

out:
	mutex_unlock(&gpio_data->lock);
	return ret ? ret : n;
}
static DEVICE_ATTR(gpio, 0644, gpio_trig_gpio_show, gpio_trig_gpio_store);

static void gpio_trig_activate(struct led_classdev *led)
{
	struct gpio_trig_data *gpio_data;

	gpio_data = gpio_trig_get_data(led);
	led->trigger_data = gpio_data;
	if (!gpio_data)
		return;

	mutex_lock(&gpio_data->lock);

	if (gpio_data->gpio)
		enable_irq(gpio_to_irq(gpio_data->gpio));

	gpio_data->active = true;

	mutex_unlock(&gpio_data->lock);
}

static void gpio_trig_deactivate(struct led_classdev *led)
{
	struct gpio_trig_data *gpio_data = led->trigger_data;

	if (!gpio_data)
		return;

	mutex_lock(&gpio_data->lock);

	if (gpio_data->gpio)
		disable_irq(gpio_to_irq(gpio_data->gpio));

	flush_work(&gpio_data->work);

	gpio_data->active = false;

	mutex_unlock(&gpio_data->lock);
}

static void gpio_trig_init_led(struct led_classdev *led)
{
	int ret;
	struct gpio_trig_data *gpio_data;

	gpio_data = kzalloc(sizeof(*gpio_data), GFP_KERNEL);
	if (!gpio_data)
		return;

	INIT_WORK(&gpio_data->work, gpio_trig_work);
	mutex_init(&gpio_data->lock);
	gpio_data->led = led;

	mutex_lock(&gpio_trig_list_lock);
	list_add_tail(&gpio_data->list, &gpio_trig_list);
	mutex_unlock(&gpio_trig_list_lock);

	ret = device_create_file(led->dev, &dev_attr_gpio);
	if (ret)
		goto err_gpio;

	ret = device_create_file(led->dev, &dev_attr_inverted);
	if (ret)
		goto err_inverted;

	ret = device_create_file(led->dev, &dev_attr_desired_brightness);
	if (ret)
		goto err_brightness;

	return;


err_brightness:
	device_remove_file(led->dev, &dev_attr_inverted);

err_inverted:
	device_remove_file(led->dev, &dev_attr_gpio);

err_gpio:
	kfree(gpio_data);
}

static void gpio_trig_destroy_led(struct led_classdev *led)
{
	struct gpio_trig_data *gpio_data;

	gpio_data = gpio_trig_get_data(led);
	if (!gpio_data)
		return;

	device_remove_file(led->dev, &dev_attr_gpio);
	device_remove_file(led->dev, &dev_attr_inverted);
	device_remove_file(led->dev, &dev_attr_desired_brightness);

	if (gpio_data->gpio != 0)
		free_irq(gpio_to_irq(gpio_data->gpio), led);

	mutex_lock(&gpio_trig_list_lock);
	list_del(&gpio_data->list);
	mutex_unlock(&gpio_trig_list_lock);

	kfree(gpio_data);
}

static struct led_trigger gpio_led_trigger = {
	.name		= "gpio",
	.activate	= gpio_trig_activate,
	.deactivate	= gpio_trig_deactivate,
	.init_led	= gpio_trig_init_led,
	.destroy_led	= gpio_trig_destroy_led,
};

static int __init gpio_trig_init(void)
{
	return led_trigger_register(&gpio_led_trigger);
}
module_init(gpio_trig_init);

static void __exit gpio_trig_exit(void)
{
	led_trigger_unregister(&gpio_led_trigger);
}
module_exit(gpio_trig_exit);

MODULE_AUTHOR("Felipe Balbi <me@felipebalbi.com>");
MODULE_DESCRIPTION("GPIO LED trigger");
MODULE_LICENSE("GPL");
