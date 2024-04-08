#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <fuse_lowlevel.h>

#include <gpgme++/context.h>
#include <gpgme++/global.h>
#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/engineinfo.h>

#include <unistd.h>

#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>

std::unique_ptr<GpgME::Context> ctx;
std::string encryptedFilePath;
std::vector<char> decryptedData;

static int gpgfs_getattr(const char *path, struct stat *stbuf, [[maybe_unused]] struct fuse_file_info *fi)
{
	if(std::string_view{path} != "/")
		return -ENOENT;

	std::filesystem::path p(encryptedFilePath);
	if(!std::filesystem::exists(p)) {
		return -ENOENT;
	}

	std::error_code ec;
	auto size = std::filesystem::file_size(p, ec);
	if(ec) {
		return -EIO;
	}

	stbuf->st_mode = S_IFREG | 0600;
	stbuf->st_nlink = 1;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = size; // this seems to be a good guess for the decrypted size
	stbuf->st_blocks = 0;
	stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

	return 0;
}

static int gpgfs_open(const char *path, [[maybe_unused]] struct fuse_file_info *fi)
{
	if(std::string_view{path} != "/") {
		return -ENOENT;
	}
	if(!decryptedData.empty()) {
		return 0;
	}

	std::vector<char> data;
	{
		std::ifstream in(encryptedFilePath, std::ios::ate);
		if(!in) {
			return -ENOENT;
		}
		data.resize(in.tellg());
		in.seekg(std::ios::beg);
		in.read(data.data(), data.size());
	}

    GpgME::Data in(data.data(), data.size(), false);
    GpgME::Data out;

    auto res = ctx->decrypt(in, out);
	if(res.error()) {
		return -EIO;
	}

	int size = out.seek(0, SEEK_END);
	decryptedData.resize(size);
	out.seek(0, SEEK_SET);
	out.read(decryptedData.data(), decryptedData.size());

	return 0;
}

static int gpgfs_close(const char *path, struct fuse_file_info *fi)
{
	if(std::string_view{path} != "/") {
		return -ENOENT;
	}

	// TODO: cache decrypted result for limited time
	//decryptedData.clear();

	return 0;
}

static int gpgfs_read(const char *path, char *buf, size_t size, off_t offset, [[maybe_unused]] struct fuse_file_info *fi)
{
	if(std::string_view{path} != "/")
		return -ENOENT;

	if (offset >= decryptedData.size())
		return -1;

	int s = std::min(decryptedData.size() - offset, size);
	std::copy(decryptedData.begin() + offset, decryptedData.begin() + offset + s, buf);
	return s;
}

static const struct fuse_operations gpgfs_operations = {
	.getattr	= gpgfs_getattr,
	.open		= gpgfs_open,
	.read		= gpgfs_read,
	.release    = gpgfs_close,
};

int main(int argc, char *argv[])
{
	std::vector<char*> args(argv, argv+argc);
	encryptedFilePath = args.at(1);
	args.erase(args.begin()+1); // remove src path from arguments

	GpgME::initializeLibrary();
    ctx = GpgME::Context::create(GpgME::Protocol::OpenPGP);

    return fuse_main(args.size(), args.data(), &gpgfs_operations, NULL);
}
