
#include <string.h>
#include <errno.h>
#include <sys/auxv.h>

// for dup2()
#include <unistd.h>
// for open()
#include <fcntl.h>
// for tcgetattr()
#include <termios.h>
// for mmap()
#include <sys/mman.h>
// for stat()
#include <sys/stat.h>
// for ioctl()
#include <sys/ioctl.h>

#include <mlibc/ensure.h>
#include <mlibc/cxx-support.hpp>
#include <mlibc/frigg-alloc.hpp>
#include <mlibc/posix-pipe.hpp>

#include <frigg/vector.hpp>
#include <frigg/hashmap.hpp>
#include <frigg/string.hpp>
#include <frigg/protobuf.hpp>

#include <posix.frigg_pb.hpp>
#include <fs.frigg_pb.hpp>

HelHandle __mlibc_getPassthrough(int fd) {
	auto handle = cacheFileTable()[fd];
	__ensure(handle);
	return handle;
}

int chroot(const char *path) {
	HelAction actions[3];

	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::CHROOT);
	req.set_path(frigg::String<MemoryAllocator>(getAllocator(), path));

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
	return 0;
}

int access(const char *path, int mode) {
	HelAction actions[3];

	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::ACCESS);
	req.set_path(frigg::String<MemoryAllocator>(getAllocator(), path));

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	if(resp.error() == managarm::posix::Errors::FILE_NOT_FOUND) {
		errno = ENOENT;
		return -1;
	}else{
		__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
		return 0;
	}
}

int stat(const char *__restrict path, struct stat *__restrict result) {
	HelAction actions[3];
	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::STAT);
	req.set_path(frigg::String<MemoryAllocator>(getAllocator(), path));

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	if(resp.error() == managarm::posix::Errors::FILE_NOT_FOUND) {
		errno = ENOENT;
		return -1;
	}else{
		__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
		memset(result, 0, sizeof(struct stat));
		result->st_dev = 1;
		result->st_ino = resp.inode_num();
		result->st_mode = resp.mode() | S_IFREG;
		result->st_nlink = resp.num_links();
		result->st_uid = resp.uid();
		result->st_gid = resp.gid();
		result->st_rdev = 0;
		result->st_size = resp.file_size();
		result->st_atim.tv_sec = resp.atime_secs();
		result->st_atim.tv_nsec = resp.atime_nanos();
		result->st_mtim.tv_sec = resp.mtime_secs();
		result->st_mtim.tv_nsec = resp.mtime_nanos();
		result->st_ctim.tv_sec = resp.ctime_secs();
		result->st_ctim.tv_nsec = resp.ctime_nanos();
		result->st_blksize = 4096;
		result->st_blocks = resp.file_size() / 512 + 1;
		return 0;
	}
}

int fstat(int fd, struct stat *result) {
	HelAction actions[3];
	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::FSTAT);
	req.set_fd(fd);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
	memset(result, 0, sizeof(struct stat));
	result->st_dev = 1;
	result->st_ino = resp.inode_num();
	result->st_mode = resp.mode() | S_IFREG;
	result->st_nlink = resp.num_links();
	result->st_uid = resp.uid();
	result->st_gid = resp.gid();
	result->st_rdev = 0;
	result->st_size = resp.file_size();
	result->st_atim.tv_sec = resp.atime_secs();
	result->st_atim.tv_nsec = resp.atime_nanos();
	result->st_mtim.tv_sec = resp.mtime_secs();
	result->st_mtim.tv_nsec = resp.mtime_nanos();
	result->st_ctim.tv_sec = resp.ctime_secs();
	result->st_ctim.tv_nsec = resp.ctime_nanos();
	result->st_blksize = 4096;
	result->st_blocks = resp.file_size() / 512 + 1;
	return 0;
}

int open(const char *path, int flags, ...) {
//	frigg::infoLogger.log() << "mlibc: open(\""
//			<< path << "\") called!" << frigg::EndLog();
	HelAction actions[3];

	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::OPEN);
	req.set_path(frigg::String<MemoryAllocator>(getAllocator(), path));

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);
	
	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	if(resp.error() == managarm::posix::Errors::FILE_NOT_FOUND) {
		errno = ENOENT;
		return -1;
	}else{
		__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
		return resp.fd();
	}
}

ssize_t read(int fd, void *data, size_t max_size) {
	//frigg::infoLogger() << "read() " << max_size << frigg::EndLog();
	HelAction actions[4];
	globalQueue.trim();

	auto handle = cacheFileTable()[fd];
	__ensure(handle);

	managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_req_type(managarm::fs::CntReqType::READ);
	req.set_fd(fd);
	req.set_size(max_size);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = kHelItemChain;
	actions[3].type = kHelActionRecvToBuffer;
	actions[3].flags = 0;
	actions[3].buffer = data;
	actions[3].length = max_size;
	HEL_CHECK(helSubmitAsync(handle, actions, 4,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);
	auto recv_data = parseLength(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);
	HEL_CHECK(recv_data->error);

	managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
/*	if(resp.error() == managarm::fs::Errors::NO_SUCH_FD) {
		errno = EBADF;
		return -1;
	}else*/ if(resp.error() == managarm::fs::Errors::END_OF_FILE) {
		return 0;
	}
	__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
	return recv_data->length;
}

ssize_t write(int fd, const void *data, size_t size) {
	HelAction actions[4];
	globalQueue.trim();

	auto handle = cacheFileTable()[fd];
	__ensure(handle);

//	frigg::infoLogger.log() << "write()" << frigg::EndLog();
	managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_req_type(managarm::fs::CntReqType::WRITE);
	req.set_fd(fd);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionSendFromBuffer;
	actions[2].flags = kHelItemChain;
	actions[2].buffer = const_cast<void *>(data);
	actions[2].length = size;
	actions[3].type = kHelActionRecvInline;
	actions[3].flags = 0;
	HEL_CHECK(helSubmitAsync(handle, actions, 4,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto send_data = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(send_data->error);
	HEL_CHECK(recv_resp->error);

	managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

	// TODO: implement NO_SUCH_FD
/*	if(resp.error() == managarm::fs::Errors::NO_SUCH_FD) {
		errno = EBADF;
		return -1;
	}else*/ if(resp.error() == managarm::fs::Errors::SUCCESS) {
		//FIXME: handle partial writes
		return size;
	}else{
		__ensure(!"Unexpected error");
		__builtin_unreachable();
	}
}

off_t lseek(int fd, off_t offset, int whence) {
	HelAction actions[3];
	globalQueue.trim();

	auto handle = cacheFileTable()[fd];
	__ensure(handle);
	
	managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_fd(fd);
	req.set_rel_offset(offset);

	if(whence == SEEK_SET) {
		req.set_req_type(managarm::fs::CntReqType::SEEK_ABS);
	}else if(whence == SEEK_CUR) {
		req.set_req_type(managarm::fs::CntReqType::SEEK_REL);
	}else if(whence == SEEK_END) {
		req.set_req_type(managarm::fs::CntReqType::SEEK_EOF);
	}else{
		frigg::panicLogger() << "Illegal whence argument" << frigg::endLog;
	}
	
	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(handle, actions, 3,
			globalQueue.getQueue(), 0, 0));
	
	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);
	
	managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
	return resp.offset();
}

HelHandle __raw_map(int fd) {
	HelAction actions[4];
	globalQueue.trim();

	auto handle = cacheFileTable()[fd];
	__ensure(handle);
	
	managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_req_type(managarm::fs::CntReqType::MMAP);
	req.set_fd(fd);
	
	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = kHelItemChain;
	actions[3].type = kHelActionPullDescriptor;
	actions[3].flags = 0;
	HEL_CHECK(helSubmitAsync(handle, actions, 4,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);
	auto pull_memory = parseHandle(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);
	HEL_CHECK(pull_memory->error);
	
	managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
	return pull_memory->handle;
}

int close(int fd) {
	HelAction actions[3];
	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::CLOSE);
	req.set_fd(fd);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));
	
	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);
	
	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	
	if(resp.error() == managarm::posix::Errors::NO_SUCH_FD) {
		errno = EBADF;		
		return -1;
	}else if(resp.error() == managarm::posix::Errors::SUCCESS) {
		return 0;
	}else{
		__ensure(!"Unexpected error");
		__builtin_unreachable();
	}
}

int dup2(int src_fd, int dest_fd) {
	HelAction actions[4];

	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::DUP2);
	req.set_fd(src_fd);
	req.set_newfd(dest_fd);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = kHelItemChain;
	actions[3].type = kHelActionPullDescriptor;
	actions[3].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 4,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);
	
	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
	return resp.fd();
}

int fcntl(int fd, int request, ...) {
	if(request == F_DUPFD) {
		return dup2(fd, -1);
	}else if(request == F_DUPFD_CLOEXEC) {
		frigg::infoLogger() << "\e[31mmlibc: fcntl(F_DUPFD_CLOEXEC) is not implemented correctly"
				<< "\e[39m" << frigg::endLog;
		return dup2(fd, -1);
	}else{
		frigg::infoLogger() << "\e[31mmlibc: Unexpected fcntl() request: "
				<< request << "\e[39m" << frigg::endLog;
		errno = EINVAL;
		return -1;
	}
}

int isatty(int fd) {
	HelAction actions[3];
	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::IS_TTY);
	req.set_fd(fd);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	if(resp.error() ==  managarm::posix::Errors::BAD_FD) {
		errno = ENOTTY;
		return 0;
	}else{
		__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
		return 1;
	}
}

thread_local frigg::String<MemoryAllocator> __mlibc_ttynameCache(getAllocator());

char *ttyname(int fd) {
	HelAction actions[3];
	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::TTY_NAME);
	req.set_fd(fd);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	if(resp.error() ==  managarm::posix::Errors::BAD_FD) {
		errno = ENOTTY;
		return nullptr;
	}else{
		__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
		__mlibc_ttynameCache = resp.path();
		return __mlibc_ttynameCache.data();
	}
}

void *mmap(void *hint, size_t size, int prot, int flags, int fd, off_t offset) {
	__ensure(!hint);

	HelAction actions[3];
	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::VM_MAP);
	req.set_size(size);
	req.set_mode(prot);
	req.set_flags(flags);
	req.set_fd(fd);
	req.set_rel_offset(offset);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
	return reinterpret_cast<void *>(resp.offset());
}

int munmap(void *pointer, size_t size) {
	HEL_CHECK(helUnmapMemory(kHelNullHandle, pointer, size));
	return 0;
}

int tcgetattr(int fd, struct termios *attr) {
	frigg::infoLogger() << "mlibc: Broken tcgetattr() called!" << frigg::endLog;
	attr->c_iflag = 0;
	attr->c_oflag = 0;
	attr->c_cflag = 0;
	attr->c_lflag = ECHO;
	for(size_t i = 0; i < NCCS; i++)
		attr->c_cc[i] = 0;
	attr->c_cc[VMIN] = 1;
	attr->c_cc[VTIME] = 0;
	return 0;
}

int tcsetattr(int, int, const struct termios *attr) {
	frigg::infoLogger() << "mlibc: Broken tcsetattr("
			<< (void *)attr->c_iflag << ", " << (void *)attr->c_oflag
			<< ", " << (void *)attr->c_cflag << ", " << (void *)attr->c_lflag
			<< ") called!" << frigg::endLog;
	return 0;
}

#include <sys/socket.h>

int socketpair(int domain, int type, int proto, int *fds) {
	HelAction actions[3];
	globalQueue.trim();

	managarm::posix::CntRequest<MemoryAllocator> req(getAllocator());
	req.set_request_type(managarm::posix::CntReqType::SOCKPAIR);
	req.set_domain(domain);
	req.set_socktype(type);
	req.set_protocol(proto);

	frigg::String<MemoryAllocator> ser(getAllocator());
	req.SerializeToString(&ser);
	actions[0].type = kHelActionOffer;
	actions[0].flags = kHelItemAncillary;
	actions[1].type = kHelActionSendFromBuffer;
	actions[1].flags = kHelItemChain;
	actions[1].buffer = ser.data();
	actions[1].length = ser.size();
	actions[2].type = kHelActionRecvInline;
	actions[2].flags = 0;
	HEL_CHECK(helSubmitAsync(kHelThisThread, actions, 3,
			globalQueue.getQueue(), 0, 0));

	auto element = globalQueue.dequeueSingle();
	auto offer = parseSimple(element);
	auto send_req = parseSimple(element);
	auto recv_resp = parseInline(element);

	HEL_CHECK(offer->error);
	HEL_CHECK(send_req->error);
	HEL_CHECK(recv_resp->error);

	managarm::posix::SvrResponse<MemoryAllocator> resp(getAllocator());
	resp.ParseFromArray(recv_resp->data, recv_resp->length);
	__ensure(resp.error() == managarm::posix::Errors::SUCCESS);
	__ensure(resp.fds_size() == 2);
	fds[0] = resp.fds(0);
	fds[1] = resp.fds(1);
	return 0;
}

#include <libdrm/drm.h>
#include <libdrm/drm_fourcc.h>

int ioctl(int fd, unsigned long request, void *arg) {
//	frigg::infoLogger() << "mlibc: ioctl with"
//			<< " type: 0x" << frigg::logHex(_IOC_TYPE(request))
//			<< ", number: 0x" << frigg::logHex(_IOC_NR(request))
//			<< " (raw request: " << frigg::logHex(request) << ")"
//			<< " on fd " << fd << frigg::endLog;

	auto handle = cacheFileTable()[fd];
	__ensure(handle);

	switch(request) {
	case DRM_IOCTL_VERSION: {
		auto param = reinterpret_cast<drm_version*>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
		
		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
		
		param->version_major = resp.drm_version_major();
		param->version_minor = resp.drm_version_minor();
		param->version_patchlevel = resp.drm_version_patchlevel();
		
		memcpy(param->name, resp.drm_driver_name().data(), frigg::min(param->name_len,
				resp.drm_driver_name().size()));
		memcpy(param->date, resp.drm_driver_date().data(), frigg::min(param->date_len,
				resp.drm_driver_date().size()));
		memcpy(param->desc, resp.drm_driver_desc().data(), frigg::min(param->desc_len,
				resp.drm_driver_desc().size()));

		param->name_len = resp.drm_driver_name().size();
		param->date_len = resp.drm_driver_date().size();
		param->desc_len = resp.drm_driver_desc().size();
		
		return resp.result();
	}
	case DRM_IOCTL_GET_CAP: {
		auto param = reinterpret_cast<drm_get_cap*>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
		req.set_drm_capability(param->capability);

		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		if(resp.error() == managarm::fs::Errors::ILLEGAL_ARGUMENT) {
			errno = EINVAL;
			return -1;
		}else{
			__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
			
			param->value = resp.drm_value();
			return resp.result();
		}
	}
	case DRM_IOCTL_MODE_GETRESOURCES: {
		auto param = reinterpret_cast<drm_mode_card_res *>(arg);
		HelAction actions[3];
		globalQueue.trim();
		
		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
		
		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
		
		for(size_t i = 0; i < resp.drm_fb_ids_size(); i++) {
			if(i >= param->count_fbs)
				 continue;
			auto dest = reinterpret_cast<uint32_t *>(param->fb_id_ptr);
			dest[i] = resp.drm_fb_ids(i);
		}
		param->count_fbs = resp.drm_fb_ids_size();
		
		for(size_t i = 0; i < resp.drm_crtc_ids_size(); i++) {
			if(i >= param->count_crtcs)
				 continue;
			auto dest = reinterpret_cast<uint32_t *>(param->crtc_id_ptr);
			dest[i] = resp.drm_crtc_ids(i);
		}
		param->count_crtcs = resp.drm_crtc_ids_size();
		
		for(size_t i = 0; i < resp.drm_connector_ids_size(); i++) {
			if(i >= param->count_connectors)
				 continue;
			auto dest = reinterpret_cast<uint32_t *>(param->connector_id_ptr);
			dest[i] = resp.drm_connector_ids(i);
		}
		param->count_connectors = resp.drm_connector_ids_size();
		
		for(size_t i = 0; i < resp.drm_encoder_ids_size(); i++) {
			if(i >= param->count_encoders)
				 continue;
			auto dest = reinterpret_cast<uint32_t *>(param->encoder_id_ptr);
			dest[i] = resp.drm_encoder_ids(i);
		}
		param->count_encoders = resp.drm_encoder_ids_size();

		param->min_width = resp.drm_min_width();
		param->max_width = resp.drm_max_width();
		param->min_height = resp.drm_min_height();
		param->max_height = resp.drm_max_height();
		
		return resp.result();	
	}
	case DRM_IOCTL_MODE_GETCONNECTOR: {
		auto param = reinterpret_cast<drm_mode_get_connector*>(arg);
		HelAction actions[4];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
		req.set_drm_connector_id(param->connector_id);

		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = kHelItemChain;
		actions[3].type = kHelActionRecvInline;
		actions[3].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 4,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);
		auto recv_list = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);
		HEL_CHECK(recv_list->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
		
		for(size_t i = 0; i < resp.drm_encoders_size(); i++) {
			if(i >= param->count_encoders)
				 continue;
			auto dest = reinterpret_cast<uint32_t *>(param->encoders_ptr);
			dest[i] = resp.drm_encoders(i);
		}
		param->count_encoders = resp.drm_encoders_size();
		
		for(size_t i = 0; i < resp.drm_num_modes(); i++) {
			if(i >= param->count_modes)
				 continue;
			auto dest = reinterpret_cast<drm_mode_modeinfo *>(param->modes_ptr);
			auto src = reinterpret_cast<drm_mode_modeinfo *>(recv_list->data);

			memcpy(&dest[i], &src[i], sizeof(drm_mode_modeinfo));
		}
		param->count_modes = resp.drm_num_modes();
		
		param->count_props = 0;
		param->encoder_id = resp.drm_encoder_id();
		param->connector_type = resp.drm_connector_type();
		param->connector_type_id = resp.drm_connector_type_id();
		param->connection = resp.drm_connection();
		param->mm_width = resp.drm_mm_width();
		param->mm_height = resp.drm_mm_height();
		param->subpixel = resp.drm_subpixel();
		param->pad = 0;
		
		return resp.result();
	}
	case DRM_IOCTL_MODE_GETENCODER: {
		auto param = reinterpret_cast<drm_mode_get_encoder*>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
		req.set_drm_encoder_id(param->encoder_id);

		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		param->encoder_type = resp.drm_encoder_type();
		param->crtc_id = resp.drm_crtc_id();
		param->possible_crtcs = resp.drm_possible_crtcs();
		param->possible_clones = resp.drm_possible_clones();
		
		return resp.result();
	}	
	case DRM_IOCTL_MODE_CREATE_DUMB: {
		auto param = reinterpret_cast<drm_mode_create_dumb*>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
		
		req.set_drm_width(param->width);
		req.set_drm_height(param->height);
		req.set_drm_bpp(param->bpp);
		req.set_drm_flags(param->flags);	

		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
	
		param->handle = resp.drm_handle();
		param->pitch = resp.drm_pitch();
		param->size = resp.drm_size();
	
		return resp.result();
	}
	case DRM_IOCTL_MODE_ADDFB: {
		auto param = reinterpret_cast<drm_mode_fb_cmd *>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
	
		req.set_drm_width(param->width);
		req.set_drm_height(param->height);
		req.set_drm_pitch(param->pitch);
		req.set_drm_bpp(param->bpp);
		req.set_drm_depth(param->depth);
		req.set_drm_handle(param->handle);
	
		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		param->fb_id = resp.drm_fb_id();
	
		return resp.result();
	}
	case DRM_IOCTL_MODE_ADDFB2: {
		auto param = reinterpret_cast<drm_mode_fb_cmd2 *>(arg);
		HelAction actions[3];
		globalQueue.trim();

		__ensure(param->pixel_format == DRM_FORMAT_XRGB8888);
		__ensure(!param->flags);
		__ensure(!param->modifier[0]);
		__ensure(!param->offsets[0]);

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(DRM_IOCTL_MODE_ADDFB);

		req.set_drm_width(param->width);
		req.set_drm_height(param->height);
		req.set_drm_pitch(param->pitches[0]);
		req.set_drm_bpp(32);
		req.set_drm_depth(24);
		req.set_drm_handle(param->handles[0]);
	
		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		param->fb_id = resp.drm_fb_id();
	
		return resp.result();
	}
	case DRM_IOCTL_MODE_RMFB: {
		auto param = reinterpret_cast<int *>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
	
		req.set_drm_fb_id(*param);
	
		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
	
		return resp.result();
	}
	case DRM_IOCTL_MODE_MAP_DUMB: {
		auto param = reinterpret_cast<drm_mode_map_dumb*>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);

		req.set_drm_handle(param->handle);
	
		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
	
		param->offset = resp.drm_offset();
	
		return resp.result();
	}
	case DRM_IOCTL_MODE_GETCRTC: {
		auto param = reinterpret_cast<drm_mode_crtc*>(arg);
		HelAction actions[4];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);
		req.set_drm_crtc_id(param->crtc_id);

		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = kHelItemChain;
		actions[3].type = kHelActionRecvToBuffer;
		actions[3].flags = 0;
		actions[3].buffer = &param->mode;
		actions[3].length = sizeof(drm_mode_modeinfo);
		HEL_CHECK(helSubmitAsync(handle, actions, 4,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);
		auto recv_data = parseLength(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);
		HEL_CHECK(recv_data->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		param->fb_id = resp.drm_fb_id();
		param->x = resp.drm_x();
		param->y = resp.drm_y();
		param->gamma_size = resp.drm_gamma_size();
		param->mode_valid = resp.drm_mode_valid();

		return resp.result();
	}
	case DRM_IOCTL_MODE_SETCRTC: {
		auto param = reinterpret_cast<drm_mode_crtc*>(arg);
		HelAction actions[4];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);

		for(size_t i = 0; i < param->count_connectors; i++) {
			auto dest = reinterpret_cast<uint32_t *>(param->set_connectors_ptr);
			req.add_drm_connector_ids(dest[i]);
		}
		req.set_drm_x(param->x);
		req.set_drm_y(param->y);
		req.set_drm_crtc_id(param->crtc_id);
		req.set_drm_fb_id(param->fb_id);
		req.set_drm_mode_valid(param->mode_valid);

		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionSendFromBuffer;
		actions[2].flags = kHelItemChain;
		actions[2].buffer = &param->mode;
		actions[2].length = sizeof(drm_mode_modeinfo);
		actions[3].type = kHelActionRecvInline;
		actions[3].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 4,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto send_mode = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(send_mode->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		return resp.result();
	}
	case DRM_IOCTL_MODE_PAGE_FLIP: {
		auto param = reinterpret_cast<drm_mode_crtc_page_flip *>(arg);
		HelAction actions[3];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);

		assert(!(param->flags & ~DRM_MODE_PAGE_FLIP_EVENT));
		req.set_drm_crtc_id(param->crtc_id);
		req.set_drm_fb_id(param->fb_id);

		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);

		return resp.result();
	}
	case DRM_IOCTL_MODE_DIRTYFB: {
		auto param = reinterpret_cast<drm_mode_fb_dirty_cmd*>(arg);
		HelAction actions[4];
		globalQueue.trim();

		managarm::fs::CntRequest<MemoryAllocator> req(getAllocator());
		req.set_req_type(managarm::fs::CntReqType::PT_IOCTL);
		req.set_command(request);

		req.set_drm_fb_id(param->fb_id);
		req.set_drm_flags(param->flags);
		req.set_drm_color(param->color);
		for(size_t i = 0; i < param->num_clips; i++) {
			auto dest = reinterpret_cast<drm_clip_rect *>(param->clips_ptr);
			managarm::fs::Rect<MemoryAllocator> clip(getAllocator());
			clip.set_x1(dest->x1);
			clip.set_y1(dest->y1);
			clip.set_x2(dest->x2);
			clip.set_y2(dest->y2);
			req.add_drm_clips(frigg::move(clip));
		}
	
		frigg::String<MemoryAllocator> ser(getAllocator());
		req.SerializeToString(&ser);
		actions[0].type = kHelActionOffer;
		actions[0].flags = kHelItemAncillary;
		actions[1].type = kHelActionSendFromBuffer;
		actions[1].flags = kHelItemChain;
		actions[1].buffer = ser.data();
		actions[1].length = ser.size();
		actions[2].type = kHelActionRecvInline;
		actions[2].flags = 0;
		HEL_CHECK(helSubmitAsync(handle, actions, 3,
				globalQueue.getQueue(), 0, 0));

		auto element = globalQueue.dequeueSingle();
		auto offer = parseSimple(element);
		auto send_req = parseSimple(element);
		auto recv_resp = parseInline(element);

		HEL_CHECK(offer->error);
		HEL_CHECK(send_req->error);
		HEL_CHECK(recv_resp->error);

		managarm::fs::SvrResponse<MemoryAllocator> resp(getAllocator());
		resp.ParseFromArray(recv_resp->data, recv_resp->length);
		__ensure(resp.error() == managarm::fs::Errors::SUCCESS);
	
		return resp.result();
	}
	default:
		frigg::infoLogger() << "mlibc: Unexpected ioctl with"
				<< " type: 0x" << frigg::logHex(_IOC_TYPE(request))
				<< ", number: 0x" << frigg::logHex(_IOC_NR(request))
				<< " (raw request: " << frigg::logHex(request) << ")" << frigg::endLog;
		__ensure(!"Illegal ioctl request");
	}
}

