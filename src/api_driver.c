#include "../hd/general.h"

#define IOCTL_MAGIC 'P'

#define PEGASUS_BLOCK_IP_V4 			_IOW(IOCTL_MAGIC, 0x01, __be32)
#define PEGASUS_BLOCK_IP_V6 			_IOW(IOCTL_MAGIC, 0x02, struct in6_addr)
#define PEGASUS_UNBLOCK_IP_V4 			_IOW(IOCTL_MAGIC, 0x03, __be32)
#define PEGASUS_UNBLOCK_IP_V6 			_IOW(IOCTL_MAGIC, 0x04, struct in6_addr)
#define PEGASUS_UNBLOCK_ALL_IPV4 		_IO(IOCTL_MAGIC, 0x05)
#define PEGASUS_UNBLOCK_ALL_IPV6 		_IO(IOCTL_MAGIC, 0x06)

#define PEGASUS_BLOCK_ALL_IPV4_TRAFFIC 		_IO(IOCTL_MAGIC, 0x07)
#define PEGASUS_BLOCK_ALL_IPV6_TRAFFIC 		_IO(IOCTL_MAGIC, 0x08)

#define PEGASUS_UNBLOCK_ALL_IPV4_TRAFFIC 	_IO(IOCTL_MAGIC, 0x09)
#define PEGASUS_UNBLOCK_ALL_IPV6_TRAFFIC 	_IO(IOCTL_MAGIC, 0x0A)

#define PEGASUS_BLOCK_TCP_PROTO			_IO(IOCTL_MAGIC, 0x0B)
#define PEGASUS_BLOCK_UDP_PROTO			_IO(IOCTL_MAGIC, 0x0C)
#define PEGASUS_BLOCK_ICMP_PROTO		_IO(IOCTL_MAGIC, 0x0D)


#define PEGASUS_BLOCK_EXCEPT_TCP_PROTO		_IO(IOCTL_MAGIC, 0x0E)
#define PEGASUS_BLOCK_EXCEPT_UDP_PROTO		_IO(IOCTL_MAGIC, 0x0F)
#define PEGASUS_BLOCK_EXCEPT_ICMP_PROTO		_IO(IOCTL_MAGIC, 0x10)

#define PEGASUS_PROTO_CLEAR			_IO(IOCTL_MAGIC, 0x11)
#define PEGASUS_BLOCK_ALL_PROTO			_IO(IOCTL_MAGIC, 0x12)


struct __lock_traffic
{
	bool lock_ipv4_traffic;
	bool lock_ipv6_traffic;
};


struct __lock_protocol
{
	bool tcp_proto;
	bool udp_proto;
	bool icmp_proto;
};

static struct __lock_traffic lock_traffic  = {.lock_ipv4_traffic = false, .lock_ipv6_traffic = false};
static struct __lock_protocol lock_protocol = {.tcp_proto = false, .udp_proto = false, .icmp_proto = false};
static dev_t pegasus_dev;
static struct cdev pegasus_cdev;
static struct class* pegasus_class;

static long pegasus_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{


	__be32 		ipv4;
	struct in6_addr 	ipv6;

	switch(cmd)
	{
		case PEGASUS_BLOCK_IP_V4:
			if (copy_from_user(&ipv4, (void __user*)arg, sizeof(ipv4))) {return -EFAULT;}
			if (add_ipv4_in_blocklist(ipv4) != 0) {return -EFAULT;}
			break;
		case PEGASUS_BLOCK_IP_V6:
			if (copy_from_user(&ipv6, (void __user*)arg, sizeof(struct in6_addr))) {return -EFAULT;}
			if (add_ipv6_in_blocklist(&ipv6) != 0) {return -EFAULT;}
			break;
		case PEGASUS_UNBLOCK_IP_V4:
			if (copy_from_user(&ipv4, (void __user*)arg, sizeof(ipv4))) {return -EFAULT;}
			if (delete_ipv4_from_blocklist(ipv4) != 0) {return -EFAULT;}
			break;
		case PEGASUS_UNBLOCK_IP_V6:
			if (copy_from_user(&ipv6, (void __user*)arg, sizeof(struct in6_addr))) {return -EFAULT;}
			if (delete_ipv6_from_blocklist(&ipv6) != 0) {return -EFAULT;}
			break;
		case PEGASUS_UNBLOCK_ALL_IPV4:
			if (unblock_all_ipv4() != 0) {return -EFAULT;}
			break;
		case PEGASUS_UNBLOCK_ALL_IPV6:
			if (unblock_all_ipv6() != 0) {return -EFAULT;}
			break;
		case PEGASUS_BLOCK_ALL_IPV4_TRAFFIC:
			lock_traffic.lock_ipv4_traffic = true;
			break;
		case PEGASUS_BLOCK_ALL_IPV6_TRAFFIC:
			lock_traffic.lock_ipv6_traffic = true;
			break;
		case PEGASUS_UNBLOCK_ALL_IPV4_TRAFFIC:
			lock_traffic.lock_ipv4_traffic = false;
			break;
		case PEGASUS_UNBLOCK_ALL_IPV6_TRAFFIC:
			lock_traffic.lock_ipv6_traffic = false;
			break;
		case PEGASUS_BLOCK_TCP_PROTO:
			lock_protocol.tcp_proto = true;
			lock_protocol.udp_proto = false;
			lock_protocol.icmp_proto = false;
			break;
		case PEGASUS_BLOCK_UDP_PROTO:
			lock_protocol.tcp_proto = false;
			lock_protocol.udp_proto = true;
			lock_protocol.icmp_proto = false;
			break;
		case PEGASUS_BLOCK_ICMP_PROTO:
			lock_protocol.tcp_proto = false;
			lock_protocol.udp_proto = false;
			lock_protocol.icmp_proto = true;
			break;
		case PEGASUS_BLOCK_EXCEPT_TCP_PROTO:
			lock_protocol.tcp_proto = false;
			lock_protocol.udp_proto = true;
			lock_protocol.icmp_proto = true;
			break;
		case PEGASUS_BLOCK_EXCEPT_UDP_PROTO:
			lock_protocol.tcp_proto = true;
			lock_protocol.udp_proto = false;
			lock_protocol.icmp_proto = true;
			break;
		case PEGASUS_BLOCK_EXCEPT_ICMP_PROTO:
			lock_protocol.tcp_proto = true;
			lock_protocol.udp_proto = true;
			lock_protocol.icmp_proto = false;
			break;
		case PEGASUS_BLOCK_ALL_PROTO:
			lock_protocol.tcp_proto = true;
			lock_protocol.udp_proto = true;
			lock_protocol.icmp_proto = true;
			break;

		case PEGASUS_PROTO_CLEAR:
			lock_protocol.tcp_proto = false;
			lock_protocol.udp_proto = false;
			lock_protocol.icmp_proto = false;
			break;
		default:
			LOG(KERN_ERR, "Operation not supported\n");
			return -ENOTTY;
			break;
	}

	return 0;
}
u8 check_protocol(void)
{
	if (!lock_protocol.tcp_proto && !lock_protocol.udp_proto && !lock_protocol.icmp_proto) {return NOT_PROTOCOL_FILTER;}
	if (lock_protocol.tcp_proto && !lock_protocol.udp_proto && !lock_protocol.icmp_proto) {return ONLY_TCP;}
	if (!lock_protocol.tcp_proto && lock_protocol.udp_proto && !lock_protocol.icmp_proto) {return ONLY_UDP;}
	if (!lock_protocol.tcp_proto && !lock_protocol.udp_proto && lock_protocol.icmp_proto) {return ONLY_ICMP;}

	if (!lock_protocol.tcp_proto && lock_protocol.udp_proto && lock_protocol.icmp_proto) {return EXCEPT_TCP;}
	if (lock_protocol.tcp_proto && !lock_protocol.udp_proto && lock_protocol.icmp_proto) {return EXCEPT_UDP;}
	if (lock_protocol.tcp_proto && lock_protocol.udp_proto && !lock_protocol.icmp_proto) {return EXCEPT_ICMP;}

	return ALL_PROTO;
}

bool ipv4_is_lock(void)
{
	return lock_traffic.lock_ipv4_traffic;
}

bool ipv6_is_lock(void)
{
	return lock_traffic.lock_ipv6_traffic;
}


static int 	pegasus_open(struct inode* inode, struct file* file) { return 0; }
static int 	pegasus_release(struct inode* inode, struct file* file) { return 0; }
static ssize_t 	pegasus_read(struct file* file, char __user* buffer, size_t size, loff_t *offset) { return 0; }
static ssize_t 	pegasus_write(struct file* file, const char __user* buffer, size_t size, loff_t *offset) { return -EINVAL; }



const struct file_operations pegasus_fops =
{
	.owner 		= THIS_MODULE,
	.open 		= pegasus_open,
	.release 	= pegasus_release,
	.read 		= pegasus_read,
	.write		= pegasus_write,
	.unlocked_ioctl = pegasus_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl 	= pegasus_ioctl,
#endif
};



int pegasus_api_init(void)
{
	int err;

	err = alloc_chrdev_region(&pegasus_dev, 0, 1, DRIVER_NAME);
	if (err) return err;
	cdev_init(&pegasus_cdev, &pegasus_fops);
	pegasus_cdev.owner = THIS_MODULE;
	err = cdev_add(&pegasus_cdev, pegasus_dev, 1);
	if (err) goto unregister_region;

	pegasus_class = class_create("pegasus_class");
	if (IS_ERR(pegasus_class)) { err = PTR_ERR(pegasus_class); goto del_cdev; }

	if (IS_ERR(device_create(pegasus_class, NULL, pegasus_dev, NULL, DRIVER_NAME)))
	{
		err = -ENOMEM;
		goto destroy_class;
	}

	LOG(KERN_INFO, "device /dev/pegasus created (major=%d minor=%d)\n", MAJOR(pegasus_dev), MINOR(pegasus_dev));
	return 0;

destroy_class:
	class_destroy(pegasus_class);
del_cdev:
	cdev_del(&pegasus_cdev);
unregister_region:
	unregister_chrdev_region(pegasus_dev, 1);
	return err;
}

void pegasus_api_exit(void)
{
	device_destroy(pegasus_class, pegasus_dev);
	class_destroy(pegasus_class);
	cdev_del(&pegasus_cdev);
	unregister_chrdev_region(pegasus_dev, 1);
}
