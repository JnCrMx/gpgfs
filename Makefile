gpgfs: gpgfs.cpp
	 g++ -o $@ $< -I /usr/include/fuse3/ -lfuse3 -lgpgmepp -O3 -g
