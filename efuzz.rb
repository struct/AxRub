## EFuzz, is a stupid ruby class for generating 
## fuzzing data from arrays of strings, numbers
## tags, uri's and more

module EFuzz

	## Incrementing strings
	class String
		def initialize(step, char)
			@step = step
			@char = char
			@orig = char
			@cur = ::String.new
		end

		def next
			@cur = @cur + @char * @step
		end

		def size
			@cur.length
		end
	end

	## URI test cases
	class Uri
		def initialize
			@uris = [ 'http://', 'https://', 'ftp://', 'mailto://', 'aim://', 'file://', 'dns://',
				'fax://', 'imap://', 'ldap://', 'ldaps://', 'smb://', 'pop://', 'rtsp://', 'snmp://',
				'telnet://', 'xmpp://', 'chrome://', 'feed://', 'irc://', 'mms://', 'ssh://',
				'sftp://', 'sms://', 'url://', 'about://', 'sip://', 'h323://' ]
		end

		def next
			@uris.shift
		end

		def size
			@uris.size
		end
	end

	## Various open tags
	class TagsOpen
		def initialize
			@tagz = [ '<xml>', '<html>', '<script>' ]
		end

		def next
			@tagz.shift
		end

		def size
			@tagz.size
		end
	end

	## Various close tags
	class TagsClose
		def initialize
			@tagz = [ '</xml>', '</html>', '</script>' ]
		end

		def next
			@tagz.shift
		end

		def size
			@tagz.size
		end
	end

	## Attack strings
	class Attacks
		def initialize
			## Some of these are stolen from DFuzz
			@attacks = [ "%n%n%n%n%n%n%n%n%n%n%n", "%252n%252n%252n%252n%252n", "%x%x%x%x", "%252x%252x%252x%252x",
				'<script>alert(1)</script>', '"><script>alert(1)</script>', '\'OR 1=1--', '\'--', '--',
                "../../../../../../../../../../../../../etc/passwd",
                "../../../../../../../../../../../../../etc/passwd%00",
                "../../../../../../../../../../../../../boot.ini",
                "../../../../../../../../../../../../../boot.ini%00",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini",
                "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini%00",
                ".../.../.../.../.../.../.../.../.../.../.../.../.../etc/passwd",
                ".../.../.../.../.../.../.../.../.../.../.../.../.../etc/passwd%00",
                ".../.../.../.../.../.../.../.../.../.../.../.../.../boot.ini",
                ".../.../.../.../.../.../.../.../.../.../.../.../.../boot.ini%00",
                "...\\...\\...\\...\\...\\...\\...\\...\\...\\...\\boot.ini",
                "...\\...\\...\\...\\...\\...\\...\\...\\...\\...\\boot.ini%00",
                "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00",
                "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini",
                "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fboot.ini%00",
                "A0`~!@#\$\%^&*()-_=+[]{}\\|;:',.<>/?\"" ]
		end

		def next
			@attacks.shift
		end

		def size
			@attacks.size
		end
	end

	## An array of integers
	class Int
		def initialize
			@intz = [ -1, 0, 64, 128, 256, 512, 1024, 4096, 8092, 16384, 65535,
				0x00000000, 0x0000FF00, 0x00FF0000, 0xFF000000, 0x80000000,
				0xFFFF0000, 0xFFFFFFFF, 0x7FFFFFFFF, 0xC0000000, 0x40000000 ]
		end

		def next
			@intz.shift
		end

		def size
			@intz.size
		end
	end

	## An array of shorts
	class Short
		def initialize
			@shortz = [ 0x0000, 0x00ff, 0xff00, 0x0ff0, 0xffff, 0x7f00, 0x007f, 0x8000, 0x0080 ]
		end

		def next
			@shortz.shift
		end

		def size
			@shortz.size
		end
	end

	## An array of bytes
	class Byte
		def initialize
			## Respectfully stolen from DFuzz
            @bytez = [ "0", "~", "`", "!", "@", "#", "$", "%", "^", "&",
            	"*", "(", ")", "-", "=", "+", "[", "]", "\\", "|", ";",
                ":", "'", "\"", ",", "<", ".", ">", "/", "?",
		        " ", "~", "_", "{", "}", "\x7f","\x00","\x01",
        		"\x02","\x03","\x04","\x05", "\x06","\x07","\x08","\x09",
		        "\x0a","\x0b","\x0c","\x0d", "\x0e","\x0f","\x10","\x11",
        		"\x12","\x13","\x14","\x15", "\x16","\x17","\x18","\x19",
		        "\x1a","\x1b","\x1c","\x1d", "\x1e","\x1f",
        		"\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87",
		        "\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e","\x8f",
		        "\x90","\x91","\x92","\x93","\x94","\x95","\x96","\x97",
		        "\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f",
        		"\xa0","\xa1","\xa2","\xa3","\xa4","\xa5","\xa6","\xa7",
		        "\xa8","\xa9","\xaa","\xab","\xac","\xad","\xae","\xaf",
        		"\xb0","\xb1","\xb2","\xb3","\xb4","\xb5","\xb6","\xb7",
		        "\xb8","\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf",
        		"\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6","\xc7",
		        "\xc8","\xc9","\xca","\xcb","\xcc","\xcd","\xce","\xcf",
        		"\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7",
		        "\xd8","\xd9","\xda","\xdb","\xdc","\xdd","\xde","\xdf",
		        "\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7",
		        "\xe8","\xe9","\xea","\xeb","\xec","\xed","\xee","\xef",
        		"\xf0","\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7",
				"\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff" ]
		end

		def next
			@bytez.shift
		end

		def size
			@bytez.size
		end
	end

	## A bunch of magic bytes
	class MagicBytes
		def initialize
			@magic = [ "MZ", ".ELF", "%PDF", "GIF87a", "GIF89a", "\xFF\D8", "\xFF\xD9",
				"\xFE\xFF", "\xFF\xFE", "\x42\x5a", "\x1f\x8b" ]
		end

		def next
			@magic.shift
		end

		def size
			@magic.size
		end
	end
end

## EFuzz Test harness
if $0 == __FILE__
	puts "\n--\nSTRINGS"
	a = EFuzz::String.new(1, 'A')
	0.upto(20) { puts "#{a.next} #{a.size}" }

	puts "\n--\nURIs"
	a = EFuzz::Uri.new
	puts a.size
	0.upto(a.size) { print "#{a.next} " }

	puts "\n--\nOpen Tags"
	a = EFuzz::TagsOpen.new
	puts a.size
	0.upto(a.size) { print "#{a.next} " }

	puts "\n--\nClose Tags"
	a = EFuzz::TagsClose.new
	puts a.size
	0.upto(a.size) { print "#{a.next} " }

	puts "\n--\nAttacks"
	a = EFuzz::Attacks.new
	puts a.size
	0.upto(a.size) { puts "#{a.next} " }

	puts "\n--\nINTS"
	a = EFuzz::Int.new
	puts a.size
	0.upto(a.size) { print "#{a.next} " }

	puts "\n--\nSHORTS"
	a = EFuzz::Short.new
	puts a.size
	0.upto(a.size) { print "#{a.next} " }

	puts "\n--\nBYTES"
	a = EFuzz::Byte.new
	puts a.size
	0.upto(a.size) { print "#{a.next}" }

	puts "\n--\nMagic BYTES"
	a = EFuzz::MagicBytes.new
	puts a.size
	0.upto(a.size) { print "#{a.next} " }

	puts "\nEFuzz is done"
end
