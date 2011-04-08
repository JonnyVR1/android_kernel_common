#include <linux/err.h>
#include <linux/ion.h>
#include "ion_priv.h"

struct ion_mapper *ion_system_mapper_create(void);
void ion_system_mapper_destroy(struct ion_mapper *);

struct ion_mapper *ion_mapper_create(enum ion_mapper_type type)
{
	struct ion_mapper *mapper = NULL;

	switch (type) {
		case ION_SYSTEM_MAPPER:
			mapper = ion_system_mapper_create();
			break;
		default:
			pr_err("%s: invalid mapper type %d.\n", __func__, type);
			return ERR_PTR(-EINVAL);
	}
	return mapper;
}

void ion_mapper_destroy(struct ion_mapper *mapper)
{	
	if (!mapper)
		return;

	switch (mapper->type) {
		case ION_SYSTEM_MAPPER:
			ion_system_mapper_destroy(mapper);
			break;
		default:
			pr_err("%s: invalid mapper type %d.\n", __func__, 
			       mapper->type);
	}
}
