#include "../hd/general.h"


static int __init pegasus_init(void)
{
	LOG(KERN_INFO, "Start driver\n");
	int ret = 0;
	ret = register_storage();
	if (ret != 0) {goto err;}
	ret = pegasus_api_init();
	if (ret != 0) {goto err;}
	init_filter();
	return 0;
err:
	LOG(KERN_INFO, "err: %d\n", ret);
	return ret;
}



static void __exit pegasus_exit(void)
{
	LOG(KERN_INFO, "Exit driver\n");
	exit_filter();
	unregister_storage();
	pegasus_api_exit();

	return;
}


module_init(pegasus_init);
module_exit(pegasus_exit);
MODULE_LICENSE("GPL");
