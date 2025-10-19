#include "../hd/general.h"


struct __storage_ips
{
	__be32* 		ipv4_blocklist_arr;
	size_t 			size_ipv4;
	size_t			count_elem_ipv4;
	size_t 			current_empty_elem_ipv4;

	struct in6_addr* 	ipv6_blocklist_arr;
	size_t 			size_ipv6;
	size_t			count_elem_ipv6;
	size_t 			current_empty_elem_ipv6;



};


static struct __storage_ips* storage_ips;


static int init_storage(void)
{
	LOG(KERN_INFO, "\n");
	storage_ips = (struct __storage_ips*)kzalloc(sizeof(struct __storage_ips), GFP_KERNEL);
	if (!storage_ips) {return -ENOMEM;}

	storage_ips->size_ipv4 = 10;
	storage_ips->size_ipv6 = 5;


	storage_ips->ipv4_blocklist_arr = (__be32*)kzalloc(sizeof(__be32) * storage_ips->size_ipv4, GFP_KERNEL);
	storage_ips->ipv6_blocklist_arr = (struct in6_addr*)kzalloc(sizeof(struct in6_addr) * storage_ips->size_ipv6, GFP_KERNEL);
	if (!storage_ips->ipv4_blocklist_arr || !storage_ips->ipv6_blocklist_arr) {goto buffers_free;}
	storage_ips->current_empty_elem_ipv4 = 0;
	storage_ips->current_empty_elem_ipv6 = 0;


	//87.250.250.246
	//185.205.130.37
	/*
	char ip1[] = "87.250.250.246";
	char ip2[] = "185.205.130.37";
	__be32 tmp;

	if (in4_pton(ip1, -1, (u8 *)&tmp, -1, NULL) == 1)
		add_ipv4_in_blocklist(tmp);
	else
		LOG(KERN_ERR, "bad ip: %s\n", ip1);

	if (in4_pton(ip2, -1, (u8 *)&tmp, -1, NULL) == 1)
		add_ipv4_in_blocklist(tmp);
	else
		LOG(KERN_ERR, "bad ip: %s\n", ip2);
	*/

	return 0;

buffers_free:
	if (storage_ips->ipv4_blocklist_arr) {kfree(storage_ips->ipv4_blocklist_arr);}
	if (storage_ips->ipv6_blocklist_arr) {kfree(storage_ips->ipv6_blocklist_arr);}
	return -ENOMEM;
}


static void delete_storage(void)
{
	if (storage_ips)
	{
		if (storage_ips->ipv4_blocklist_arr) {kfree(storage_ips->ipv4_blocklist_arr);}
		if (storage_ips->ipv6_blocklist_arr) {kfree(storage_ips->ipv6_blocklist_arr);}
	}

	kfree(storage_ips);
}

#define STEP_SIZE 5
static int ipv4_realloc(void)
{
	__be32* temp_arr = (__be32*)kzalloc(sizeof(__be32) * storage_ips->size_ipv4, GFP_KERNEL);
	if (!temp_arr) {goto err_alloc;}

	for (size_t index = 0; index < storage_ips->size_ipv4; ++index)
	{
		temp_arr[index] =  storage_ips->ipv4_blocklist_arr[index];
	}

	kfree(storage_ips->ipv4_blocklist_arr);
	storage_ips->ipv4_blocklist_arr = (__be32*)kzalloc(sizeof(__be32) * storage_ips->size_ipv4 + STEP_SIZE, GFP_KERNEL);
	if (!storage_ips->ipv4_blocklist_arr) {goto err_realloc;}

	for (size_t index; index < storage_ips->size_ipv4; ++index)
	{
		storage_ips->ipv4_blocklist_arr[index]=  temp_arr[index];
	}
	kfree(temp_arr);
	storage_ips->current_empty_elem_ipv4 = storage_ips->size_ipv4 + 1;
	storage_ips->size_ipv4 +=  STEP_SIZE;
	return 0;

err_alloc:
	return -ENOMEM;
err_realloc:
	kfree(temp_arr);
	return -ENOMEM;
}



static int ipv6_realloc(void)
{
	struct in6_addr* temp_arr = (struct in6_addr*)kzalloc(sizeof(struct in6_addr) * storage_ips->size_ipv6, GFP_KERNEL);
	if (!temp_arr) {goto err_alloc;}

	for (size_t index = 0; index < storage_ips->size_ipv6; ++index)
	{
		temp_arr[index] =  storage_ips->ipv6_blocklist_arr[index];
	}

	kfree(storage_ips->ipv6_blocklist_arr);
	storage_ips->ipv6_blocklist_arr = (struct in6_addr*)kzalloc(sizeof(struct in6_addr) * storage_ips->size_ipv6 + STEP_SIZE, GFP_KERNEL);
	if (!storage_ips->ipv6_blocklist_arr) {goto err_realloc;}

	for (size_t index; index < storage_ips->size_ipv6; ++index)
	{
		storage_ips->ipv6_blocklist_arr[index]=  temp_arr[index];
	}
	kfree(temp_arr);
	storage_ips->current_empty_elem_ipv6 = storage_ips->size_ipv6 + 1;
	storage_ips->size_ipv6 +=  STEP_SIZE;


	return 0;

err_alloc:
	return -ENOMEM;
err_realloc:
	kfree(temp_arr);
	return -ENOMEM;
}

#undef STEP_SIZE



static int find_empty_cell_ipv4(void)
{
	for (size_t index = 0; index < storage_ips->size_ipv4; ++index)
	{
		if (storage_ips->ipv4_blocklist_arr[index] == 0) {return index;}
	}

	return -1;
}


static int find_empty_cell_ipv6(void)
{
	for (size_t index = 0; index < storage_ips->size_ipv6; ++index)
	{
		if (ipv6_addr_any(&storage_ips->ipv6_blocklist_arr[index])) {return index;}
	}

	return -1;
}


int add_ipv4_in_blocklist(__be32 new_ip)
{
	int ret = 0;

	storage_ips->current_empty_elem_ipv4 = find_empty_cell_ipv4();
	if (storage_ips->current_empty_elem_ipv4 == -1)
	{
		LOG(KERN_INFO, "relloc\n");
		ret = ipv4_realloc();
		if (ret == -ENOMEM) {goto out;}
	}

	storage_ips->ipv4_blocklist_arr[storage_ips->current_empty_elem_ipv4] = new_ip;
	storage_ips->count_elem_ipv4++;
out:
	return ret;

}

int delete_ipv4_from_blocklist(__be32 del_ip)
{
	bool deleted = false;
	for (size_t index = 0; index < storage_ips->size_ipv4; ++index)
	{
		if (storage_ips->ipv4_blocklist_arr[index] == del_ip)
		{
			storage_ips->ipv4_blocklist_arr[index] = 0;
			deleted = true;
		}
	}
	if (deleted)
	{
		storage_ips->count_elem_ipv4--;
		return 0;
	}
	return -1;
}


int add_ipv6_in_blocklist(struct in6_addr* new_ip)
{
	int ret = 0;

	storage_ips->current_empty_elem_ipv6 = find_empty_cell_ipv6();
	if (storage_ips->current_empty_elem_ipv6 == -1)
	{
		LOG(KERN_INFO, "relloc\n");
		ret = ipv6_realloc();
		if (ret == -ENOMEM) {goto out;}
	}

	memcpy(&storage_ips->ipv6_blocklist_arr[storage_ips->current_empty_elem_ipv6], new_ip, sizeof(struct in6_addr));
	storage_ips->count_elem_ipv6++;
out:
	return ret;
}

int delete_ipv6_from_blocklist(const struct in6_addr *del_ip)
{
	bool deleted = false;
	for (size_t index = 0; index < storage_ips->size_ipv6; ++index)
	{
		if (ipv6_addr_equal(&storage_ips->ipv6_blocklist_arr[index], del_ip))
		{
			memset(&storage_ips->ipv6_blocklist_arr[index], 0, sizeof(struct in6_addr));
		}
	}
	if (deleted)
	{
		storage_ips->count_elem_ipv6--;
		return 0;
	}
	return -1;

}

size_t get_ipv6_arr_size(void)
{
	return storage_ips->size_ipv6;
}

size_t get_ipv4_arr_size(void)
{
	return storage_ips->size_ipv4;
}


size_t count_ipv4(void)
{
	return storage_ips->count_elem_ipv4;
}

size_t count_ipv6(void)
{
	return storage_ips->count_elem_ipv6;
}


bool check_ipv4_arr(__be32 ip)
{
	for (size_t index = 0; index < storage_ips->size_ipv4; ++index)
	{
		if (storage_ips->ipv4_blocklist_arr[index] == ip) {return true;}
	}

	return false;
}

bool check_ipv6_arr(struct in6_addr* ip)
{
	for (size_t index = 0; index < storage_ips->size_ipv6; ++index)
	{
		if (ipv6_addr_equal(&storage_ips->ipv6_blocklist_arr[index], ip)) {return true;}
	}

	return false;
}

int unblock_all_ipv4(void)
{
	if (storage_ips->count_elem_ipv4 == 0) {return 0;}
	for (size_t index = 0; index < storage_ips->count_elem_ipv4; ++index)
	{
		if (delete_ipv4_from_blocklist( storage_ips->ipv4_blocklist_arr[index]) != 0) {return -EFAULT;}
	}

	return 0;
}

int unblock_all_ipv6(void)
{
	if (storage_ips->count_elem_ipv6 == 0) {return 0;}
	for (size_t index = 0; index < storage_ips->count_elem_ipv6; ++index)
	{
		if (delete_ipv6_from_blocklist(&storage_ips->ipv6_blocklist_arr[index]) != 0) {return -EFAULT;}
	}

	return 0;
}



int register_storage(void)
{
	return init_storage();
}


void unregister_storage(void)
{
	delete_storage();
}



