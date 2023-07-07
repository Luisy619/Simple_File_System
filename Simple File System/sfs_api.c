#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "disk_emu.c"

#define DISK_NAME "BINGBONG"
#define BLOCK_SIZE 1024
#define NUM_BLOCKS 1024

#define MAX_FILE_NAME_LENGTH 20 //16 for file name and 4 for .ext
#define MAX_FILE_SIZE NUM_BLOCKS * ((BLOCK_SIZE / sizeof(int)) + 12)
//#define MAX_FILE_SIZE (BLOCK_SIZE * NUM_BLOCKS)

#define NUM_INODES 100 
#define ROOT_ADDRESS 0
#define MAGIC_NUMBER 0xABCD0005


/*--------------------------------*/
/*             BITMAP             */
/*--------------------------------*/

//Initialize bitmap with all 0s (unoccupied)
int bitmap[128 - 1];


void free_bit(int index) {
    bitmap[index] = 0;
}

void set_bit(int index) {
    bitmap[index] = 1;
}

int get_free_bit() {

    for (int i = 0; i < 100; i++) {
        if(bitmap[i] == 0) {

            return i;
        }
    }

    return -1;
}


/*--------------------------------*/
/*  SUPERBLOCK & i-NODE & FD & DE */
/*--------------------------------*/

//Super Block
typedef struct {
    int magic_number;
    int block_size;
    int fs_size;
    int inode_table_len;
    int root_dir_inode;
} superblock_t;

//i-Node
typedef struct {
    int mode;
    int link_cnt;
    int uid;
    int gid;
    int size;
    int ptrs[12];
    int ind_ptr;
} inode_t;

//File Descriptor
typedef struct {
    inode_t* inode;
    int inode_index;
    int rw_ptr;
} fd_t;

//Directory Entry
typedef struct {
    int inode_index;
    char name[MAX_FILE_NAME_LENGTH];
} dir_entry_t;

//SUPERBLOCK
superblock_t SUPERBLOCK;

//i-Node references
inode_t inode_table[NUM_INODES];
int inode_index[NUM_INODES];

//fd & dir references
fd_t fd_table[NUM_INODES];
dir_entry_t de_table[NUM_INODES];
int cur_dir_index;

void init_superblock() {
    SUPERBLOCK.magic_number = MAGIC_NUMBER;
    SUPERBLOCK.block_size = BLOCK_SIZE;
    SUPERBLOCK.fs_size = BLOCK_SIZE;
    int inode_table_len = NUM_INODES;
    int root_dir_inode = ROOT_ADDRESS;
}

void set_inode(int index, int mode, int link_cnt, int uid, int gid, int size, int ptrs[12], int ind_ptr) {
    inode_table[index].mode = mode;
    inode_table[index].link_cnt = link_cnt;
    inode_table[index].uid = uid;
    inode_table[index].gid = gid;
    inode_table[index].size = size;
    for (int i = 0; i < 12; i++) {
        inode_table[index].ptrs[i] = ptrs[i];
    }
    inode_table[index].ind_ptr = ind_ptr;

    inode_index[index] = 1;
}

void reset_inode(int index) {
    inode_table[index].mode = -1;
    inode_table[index].link_cnt = -1;
    inode_table[index].uid = -1;
    inode_table[index].gid = -1;
    inode_table[index].size = -1;
    for (int i; i < 12; i++) {
        inode_table[index].ptrs[i] = -1;
    }
    inode_table[index].ind_ptr = -1;

    inode_index[index] = 0;
}

void init_inode_table() {

    for (int i = 0; i < NUM_INODES; i++) {
        reset_inode(i);
    }
}

int get_free_inode() {

	for (int i = 0; i < NUM_INODES; i++){

		if (inode_index[i] == 0){
			inode_index[i] = 1;

			return i;
		}
	}
    
	return -1;
}

void reset_fd_table(int index) {
    fd_table[index].inode_index = -1;
}

void init_fd_table() {
    for (int i = 0; i < NUM_INODES; i++) {
        reset_fd_table(i);
    }
}

int get_free_fd() {

	for (int i = 0; i < NUM_INODES; i++){

		if (fd_table[i].inode_index == -1){

			return i;
		}
	}

	return -1;
}

void reset_de_table(int index) {
    de_table[index].inode_index = -1;

    for (int i = 0; i < MAX_FILE_NAME_LENGTH; i++) {
        de_table[index].name[i] = '\0';
    }
}

void init_de_table() {
    for (int i = 0; i < NUM_INODES; i++) {
        reset_de_table(i);
    }
}

int get_free_de() {
	for (int i = 0; i < NUM_INODES; i++){

		if (de_table[i].inode_index == -1){

			return i;
		}
	}

	return -1;
}

int find_file_inode(const char *name) {
    char *buf = malloc(sizeof(char) * MAX_FILE_NAME_LENGTH);

    for (int i = 0; i < NUM_INODES; i++) {

        if (de_table[i].inode_index != -1) {
            strcpy(buf, de_table[i].name);

            if (strcmp(buf, name) == 0) {
                free(buf);

                return de_table[i].inode_index;
            }
        }
    }

    free(buf);

    return -1;
}

int find_file_fd(const char *name) {

    int file_inode_index = find_file_inode(name);
    
    for (int i = 0; i < NUM_INODES; i++) {
        
        if (fd_table[i].inode_index == file_inode_index) {

            return fd_table[i].inode_index;
        }

        return -1;
    }
}

int find_file_de(const char *name) {

    for (int i = 0; i < NUM_INODES; i++) {
        
        if (strcmp(de_table[i].name, name)) {

            return i;
        }

        return -1;
    }

}

int num_inode_blocks() {
    int num_inode_blocks = (sizeof(inode_table)/BLOCK_SIZE);

    if (sizeof(inode_table) % BLOCK_SIZE != 0) {
        num_inode_blocks += 1;
    }

    return num_inode_blocks;
}

int num_de_blocks() {
    int num_de_blocks = (sizeof(de_table)/BLOCK_SIZE);

    if (sizeof(de_table) % BLOCK_SIZE != 0) {
        num_de_blocks += 1;
    }
}


/*--------------------------------*/
/*             mksfs              */
/*     creates the file system    */
/*--------------------------------*/

void mksfs(int fresh) {

	if (fresh == 1) {
        
        init_fd_table();
        init_de_table();
        init_fresh_disk(DISK_NAME, BLOCK_SIZE, NUM_BLOCKS);
        init_inode_table();
        init_superblock();

        cur_dir_index = 0;

        int num_inode = num_inode_blocks();
        int num_de = num_de_blocks();

        set_bit(0);

        for (int i = 1; i < num_inode + 1; i++) {
            set_bit(i);
        }

        for (int i = num_inode + 1; i < num_de + (num_inode + 1); i++) {
            set_bit(i);
        }

        set_bit(126);
        set_bit(127);

        int de_ptrs[12];

        for (int i = 0; i < num_de; i++) {
            de_ptrs[i] = i + num_inode + 1;
        }

        set_inode(ROOT_ADDRESS, 0, num_de, 0, 0, -1, de_ptrs, -1);

        write_blocks(0, 1, &SUPERBLOCK);
        write_blocks(1, num_inode, &inode_table);

        void *buf = malloc(BLOCK_SIZE * num_de);

        memcpy(buf, &de_table, sizeof(de_table));

        write_blocks(inode_table[ROOT_ADDRESS].ptrs[0], num_de, buf);

        free(buf);

        write_blocks(1022, 1, &inode_index);
        write_blocks(1023, 1, &bitmap);

	} else {

        init_fd_table();
		init_disk(DISK_NAME, BLOCK_SIZE, NUM_BLOCKS);
        
        cur_dir_index = 0;

        void *buf = malloc(BLOCK_SIZE);

		read_blocks(0, 1, buf);

		memcpy(&SUPERBLOCK, buf, sizeof(superblock_t));

        int num_inode = num_inode_blocks();

		free(buf);

		buf = malloc(BLOCK_SIZE * num_inode);

		read_blocks(1, num_inode, buf);

		memcpy(&inode_table, buf, sizeof(inode_table));

		free(buf);

		buf = malloc(BLOCK_SIZE);

		read_blocks(1022, 1 , buf);
		
        memcpy(&inode_index, buf, sizeof(inode_index));

		free(buf);

		buf = malloc(BLOCK_SIZE);
		read_blocks(1023, 1, buf);
		memcpy(&bitmap, buf, sizeof(bitmap));

		free(buf);

		buf = malloc(BLOCK_SIZE * (inode_table[ROOT_ADDRESS].link_cnt));		
		read_blocks(inode_table[ROOT_ADDRESS].ptrs[0], inode_table[ROOT_ADDRESS].link_cnt, buf);
		memcpy(&de_table, buf, sizeof(de_table));

		free(buf);
	}
}


/*--------------------------------*/
/*     nextFileName & FileSize    */
/*--------------------------------*/

int sfs_getnextfilename(char *fname) {
    for (int i = cur_dir_index; i < NUM_INODES; i++) {

        if (de_table[cur_dir_index].inode_index != -1) {
            
            strcpy(fname, de_table[cur_dir_index].name);
            cur_dir_index = i + 1;

            return 1;
        }
    }

    cur_dir_index = 0;

    return 0;
}

int sfs_getfilesize(const char* path) {
    
    int file_index = find_file_inode(path);

    if (file_index != -1) {
        
        return inode_table[file_index].size;
    }

    return -1;
}


/*--------------------------------*/
/*     Open/Close & Read/Write    */
/*--------------------------------*/

int sfs_fopen(char *name){

    if (strlen(name) > MAX_FILE_NAME_LENGTH) {

        return -1;
    }

	int file_inode = find_file_inode(name);
    int file_fd = find_file_fd(name);

    int free_inode = get_free_inode();
    int free_fd = get_free_fd();
    int free_de = get_free_de();
    int free_bit = get_free_bit();

	if (file_inode == -1 && file_fd == -1) {

        if (free_inode == -1 || free_de == -1 || free_bit == -1){
            return -1;
        }

        int new_ptrs[12];
        new_ptrs[0] = free_bit;
        
        for (int i = 1; i < 12; i++){
            new_ptrs[i] = -1;
        }

        set_inode(free_inode, 0, 1, 0, 0, 0, new_ptrs, -1);

        fd_table[free_fd].inode = &(inode_table[free_inode]);
        fd_table[free_fd].inode_index = free_inode;
        fd_table[free_fd].rw_ptr = inode_table[free_inode].size;

        de_table[free_de].inode_index = free_inode;
        strcpy(de_table[free_de].name, name);

        int num_de_blocks = (sizeof(de_table)/BLOCK_SIZE);

        if (sizeof(de_table) % BLOCK_SIZE != 0){

            num_de_blocks += 1;
        }

        inode_table[ROOT_ADDRESS].size += 1;

        void *buf = malloc(BLOCK_SIZE * num_de_blocks);
        memcpy(buf, &de_table, sizeof(de_table));
        write_blocks(inode_table[ROOT_ADDRESS].ptrs[0], num_de_blocks, buf);
        free(buf);

        int num_inode = num_inode_blocks();
        write_blocks(1, num_inode, &inode_table);
        write_blocks(1022, 1, &inode_index);
        write_blocks(1023, 1, &bitmap);

        return free_fd;

	} else {

        fd_table[file_fd].inode = &(inode_table[file_inode]);
        fd_table[file_fd].inode_index = file_inode;
        fd_table[file_fd].rw_ptr = inode_table[file_inode].size;

        return file_fd;
    }
	
    return -1;
}

int sfs_fclose(int fileID) {
	if (fd_table[fileID].inode_index == -1){

		return -1;

	} else {
		fd_table[fileID].inode_index = -1;

		return 0;	
	}
}

int sfs_fread(int fileID, char *buf, int length) {
    int rd_block[255];
    int rd_inode = fd_table[fileID].inode_index;
    int rd;
	int end;

	int start = fd_table[fileID].rw_ptr / BLOCK_SIZE;

	void *ind_buf = malloc(BLOCK_SIZE);

	if (inode_table[rd_inode].link_cnt > 12){
		read_blocks(inode_table[rd_inode].ind_ptr, 1, ind_buf);
		memcpy(&rd_block, ind_buf, BLOCK_SIZE);
	}

	void *file_buf = malloc(BLOCK_SIZE * end);

	for (int i = start; i < inode_table[rd_inode].link_cnt && i < end; i++){
		if (i >= 12){
			read_blocks(rd_block[i - 12], 1, (file_buf + (i - start) * BLOCK_SIZE));
		} else {
			read_blocks(inode_table[rd_inode].ptrs[i], 1, (file_buf + (i - start) * BLOCK_SIZE));
		}
	}

	memcpy(buf, file_buf, rd);

	fd_table[fileID].rw_ptr += rd;

	free(ind_buf);
	free(file_buf);

	return rd;
}

int sfs_fwrite(int fileID, const char *buf, int length) {
    int wr_block[255];
    int wr = length;
    int wr_inode = fd_table[fileID].inode_index;
	int wr_bytes = fd_table[fileID].rw_ptr + length;

	if (wr_bytes > MAX_FILE_SIZE){
		wr_bytes = MAX_FILE_SIZE;
		wr = MAX_FILE_SIZE - fd_table[fileID].rw_ptr;
	}

	int curr_bytes = inode_table[wr_inode].link_cnt;
	int bytes_needed = wr_bytes / BLOCK_SIZE;

	if (wr_bytes % BLOCK_SIZE != 0){
		bytes_needed += 1;
	}

	int extra_bytes = bytes_needed - curr_bytes;

    //ind_ptr
	void *ind_buf = malloc(BLOCK_SIZE);

    if (extra_bytes > 0) {

        if (inode_table[wr_inode].link_cnt + extra_bytes > 12) {
            int free_bit = get_free_bit();

            if (free_bit != 0) {
                
                return -1;
            }

            inode_table[wr_inode].ind_ptr = free_bit;
        }
    } else {

        if (inode_table[wr_inode].link_cnt > 12){

		read_blocks(inode_table[wr_inode].ind_ptr, 1, ind_buf);
		memcpy(&wr_block, ind_buf, BLOCK_SIZE);
        }
    }

	free(ind_buf);

    //ptr
	if (extra_bytes > 0){

		for (int i = inode_table[wr_inode].link_cnt; i < inode_table[wr_inode].link_cnt + extra_bytes; i++){
			int free_bit = get_free_bit();

			if (free_bit != 0){

				return -1;

			} else {

				if (i >= 12){

					wr_block[i - 12] = free_bit;

				} else {

					inode_table[wr_inode].ptrs[i] = free_bit;	
				}
			}
		}
	}

	int start = fd_table[fileID].rw_ptr / BLOCK_SIZE;
	int startOffset = fd_table[fileID].rw_ptr % BLOCK_SIZE;

	int end = bytes_needed;

	void *file_buf = malloc(BLOCK_SIZE * bytes_needed);

	for (int i = start; i < inode_table[wr_inode].link_cnt && i < end; i++){

		if (i >= 12){

			read_blocks(wr_block[i-12], 1, (file_buf + (i-start) * BLOCK_SIZE));
		} else {

			read_blocks(inode_table[wr_inode].ptrs[i], 1, (file_buf + (i-start) * BLOCK_SIZE));
		}
	}

	memcpy((file_buf + startOffset), buf, wr);
	write_blocks(1022, 1, &inode_index);

	for (int i = start; i < end; i++){

		if (i >= 12){

			write_blocks(wr_block[i-12], 1, (file_buf + (i-start) * BLOCK_SIZE));

		} else {
            
			write_blocks(inode_table[wr_inode].ptrs[i], 1, (file_buf + ((i-start) * BLOCK_SIZE)));
		}
	}

	if (inode_table[wr_inode].size < wr_bytes){
		inode_table[wr_inode].size = wr_bytes;
	} 

	inode_table[wr_inode].link_cnt += extra_bytes;
	fd_table[fileID].rw_ptr = wr_bytes;

	if (inode_table[wr_inode].link_cnt > 12){
		write_blocks(inode_table[wr_inode].ind_ptr, 1, &wr_block);
	}

	int num_inode = num_inode_blocks();

	write_blocks(1, num_inode, &inode_table);
	write_blocks(1022, 1, &inode_index);
	write_blocks(1023, 1, &bitmap);

	free(file_buf);

	return wr;
}


/*--------------------------------*/
/*          Seek & Remove         */
/*       Seek from beginning      */
/*--------------------------------*/

int sfs_fseek(int fileID, int loc) {
	fd_table[fileID].rw_ptr = loc;

    if (fd_table[fileID].rw_ptr == loc) {
        return 0;
    }

	return -1;
}

int sfs_remove(char *file) {
    int file_inode = find_file_inode(file);
    int file_fd = find_file_fd(file);
    int file_de = find_file_de(file);

	if (file_inode != -1 && file_fd != -1 && file_de != -1) {
        reset_inode(file_inode);
        reset_fd_table(file_fd);
        reset_de_table(file_de);
    }

    return -1;
}

