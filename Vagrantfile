# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://vagrantcloud.com/search.
  config.vm.define "palisade", primary: true do |palisade|
    palisade.vm.box = "ubuntu/xenial64"

    # Enable provisioning with a shell script. Additional provisioners such as
    # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
    # documentation for more information about their specific syntax and use.
    #
    # View the documentation for the provider you are using for more
    # information on available options.
    palisade.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get -y upgrade

      # dependencies
      apt-get -y install \
      		cmake
      
      # core
      apt-get -y install \
      		g++ \
		bison \
		flex \
		lzip

      # docs
      apt-get -y install \
		doxygen \
		texlive-latex-base \
		ghostscript \
		graphviz

      # audit tools
      apt-get -y install \
		python-pip \
		flawfinder \
		cppcheck \
		shellcheck \
		lcov \
		gcovr \
		valgrind
      pip install cpplint
    SHELL
  end

  config.vm.define "ubuntu", autostart: false do |ubuntu|
    ubuntu.vm.box = "ubuntu/bionic64"

    ubuntu.vm.provision "shell", inline: <<-SHELL
      apt-get update

      # core
      apt-get -y install \
      		g++ \
		bison \
		flex \
		lzip
    SHELL
  end

  config.vm.define "debian9", autostart: false do |debian9|
    debian9.vm.box = "debian/stretch64"

    debian9.vm.provision "shell", inline: <<-SHELL
	apt-get update

	# core
	apt-get -y install \
		g++ \
		flex \
		bison \
		lzip
    SHELL
  end

  # debian 8 jessie will not build
  # because the palisade library requires a version of bison
  # which is higher than the highest version packaged with the distro
  config.vm.define "debian8", autostart: false do |debian8|
    debian8.vm.box = "debian/jessie64"

    debian8.vm.provision "shell", inline: <<-SHELL
	apt-get update

	# core
	apt-get -y install \
		g++ \
		flex \
		bison \
		lzip
    SHELL
  end

  config.vm.define "fedora28", autostart: false do |fedora28|
    fedora28.vm.box = "fedora/28-cloud-base"
    fedora28.vm.box_version = "20180425"

    fedora28.vm.provision "shell", inline: <<-SHELL
    	dnf update -y

	# core
	dnf -y install \
		gcc-c++ \
		flex \
		bison \
		lzip
    SHELL
  end

  config.vm.define "fedora27", autostart: false do |fedora27|
    fedora27.vm.box = "fedora/27-cloud-base"
    fedora27.vm.box_version = "20171105"

    fedora27.vm.provision "shell", inline: <<-SHELL
      dnf update -y

      # core
      dnf -y install \
      		gcc-c++ \
		flex \
		bison \
		lzip
    SHELL
  end

  # note that centos will not build palisade out of the box
  # because the g++ compiler that is packaged is not compatible
  # meaning the compiler is not >=v5.*.*
  config.vm.define "centos", autostart: false do |centos|
    centos.vm.box = "centos/7"

    centos.vm.provision "shell", inline: <<-SHELL
      yum update -y
      yum -y install \
      		epel-release

      # core
      yum -y install \
      		gcc-c++ \
		flex \
		bison \
      		lzip
    SHELL
  end

  config.vm.define "arch", autostart: false do |arch|
    arch.vm.box = "archlinux/archlinux"

    arch.vbguest.auto_update = false

    arch.vm.provision "shell", inline: <<-SHELL
      pacman -Syu --noconfirm
      pacman -S --noconfirm \
      		make \
      		gcc \
		flex \
		bison \
		lzip
    SHELL
  end
  
  config.vm.define "tumbleweed", autostart: false do |tumbleweed|
    tumbleweed.vm.box = "opensuse/openSUSE-Tumbleweed-x86_64"
    tumbleweed.vm.box_version = "1.0.6.20180530"

    tumbleweed.vbguest.auto_update = false

    tumbleweed.vm.provision "shell", inline: <<-SHELL
      zypper -n --gpg-auto-import-key refresh
      zypper -n update
      zypper -n install \
    		gcc-c++ \
     		flex \
    		bison \
    		lzip
    SHELL
  end

  config.vm.define "suse", autostart: false do |suse|
    suse.vm.box = "opensuse/openSUSE-15.0-x86_64"
    suse.vm.synced_folder ".", "/vagrant", type: "rsync"

    suse.vbguest.auto_update = false

    suse.vm.provision "shell", inline: <<-SHELL
      zypper -n --gpg-auto-import-key refresh
      zypper -n update
      zypper -n install \
      		gcc-c++ \
		flex \
		bison \
		lzip
    SHELL
  end
  # Disable automatic box update checking. If you disable this, then
  # boxes will only be checked for updates when the user runs
  # `vagrant box outdated`. This is not recommended.
  # config.vm.box_check_update = false

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # NOTE: This will enable public access to the opened port
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine and only allow access
  # via 127.0.0.1 to disable public access
  # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  config.vm.provider "virtualbox" do |vb|
    # Display the VirtualBox GUI when booting the machine
    #vb.gui = true
 
    # Customize the amount of memory on the VM:
    vb.memory = "2048"
  end
end
