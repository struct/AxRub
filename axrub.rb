#!/usr/bin/env ruby

## AxRub 1.0
## Tested with Ruby 1.8.6 and 1.9.0

require 'socket'
require 'win32ole'
require 'efuzz'

class AxRub
	def initialize(progid, bl_file)
		@progid = progid
		@bl_file = bl_file

		begin
			@obj = WIN32OLE.new(@progid)
			ax_properties
			ax_methods
		rescue
			puts "Failed to open #{@progid}"
			exit
		end

		puts "\nMethods Found:\n"
		@ax_meths.each do |meth|
	   	    puts "#{meth.name}(" +
				meth.params.map { |p| "#{p.ole_type} #{p.name}" }.join(', ') + ")"
		end

		puts "\nProperties Found:\n"
		@ax_props.each do { |p| puts "#{p}" end

		begin
			@web_server = TCPServer.new(nil, '8080')
			puts "AxRub is listening @ http://localhost:8080"
		rescue
			puts "Failed to setup the web server, try again!"
			exit
		end
	end

	def launch_ie
		begin
			@ie = WIN32OLE.new('InternetExplorer.Application')
			@ie.visible = true
		rescue
			puts "failed to launch IE, do it yourself"
		end
	end

	def blacklist
		l = File.open(@bl_file)
		l.each do |l|
            @ax_meths.each do |m|
                if l.match(m.to_s)
					puts "Skipping #{m}"
                    @ax_meths.delete(m)
                end
            end
            @ax_props.each do |m|
                if l.match(m.to_s)
					puts "Skipping #{m}"
                    @ax_props.delete(m)
                end
            end
        end
	end

	def fuzz
		puts "\nREADY TO FUZZ!\n"

		@ax_meths.each do |meth|
		    psz = meth.size_params
   			p_ary = Array.new(psz, "0")

	   	    puts "> #{meth.name}(" + 
				meth.params.map { |p| "#{p.ole_type} #{p.name}" }.join(', ') + ")"

	    	0.upto(psz-1) do |idx|
	    	    args = p_ary.dup

				meth.params.map do |p|
				if p.ole_type !~ /I1|I2|I4|I8|R4|R8|CY|DATE|UINT|UI2|UI4|INT|LONG|PTR|DISPPARAMS|VARIANT|EXCEPINFO|GUID|VOID|BOOL|ERROR|HRESULT|DECIMAL/i
						0.upto(psz-1) do |i|
							args[i] = "\"a\""
						end
					end
				end

				meth.params.map do |p|

					init_efuzz

					case p.ole_type
						when /I1|BSTR|PSTR|PWSTR/i
							0.upto(10) do
								args[idx] = "\"#{@strings.next}\""
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							break
						when /DISPPARAMS|VARIANT|EXCEPINFO|GUID|VOID|DISPATCH/i
							0.upto(10) do
								args[idx] = "\"#{@strings.next}\""
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							0.upto(@ints.size) do
								args[idx] = @ints.next
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							break
						when /I1|I2|I4|I8|R4|R8|CY|DATE|UINT|UI2|UI4|INT|LONG|PTR|DISPPARAMS|VARIANT|EXCEPINFO|GUID|VOID|BOOL|ERROR|HRESULT|DECIMAL/i
							0.upto(@ints.size) do
								args[idx] = @ints.next
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							0.upto(@bytes.size) do
								args[idx] = @bytes.next
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							0.upto(@bytes.size) do
								args[idx] = "\"#{@bytes.next}\""
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							0.upto(@shorts.size) do
								args[idx] = @shorts.next
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							break
						else
							0.upto(10) do
								args[idx] = "\"#{@strings.next}\""
								listen("axobj.#{meth.name}(#{args.join(', ')});")
							end
							break
					end
				end
			end
	    end

		@ax_props.each do |prop|
			init_efuzz

			0.upto(10) do
				listen("axobj.#{prop} = \"#{@strings.next}\";")
			end
			0.upto(@ints.size) do
				listen("axobj.#{prop} = #{@ints.next};");
			end
			0.upto(@bytes.size) do
				listen("axobj.#{prop} = \"#{@bytes.next}\";")
			end
			0.upto(@bytes.size) do
				listen("axobj.#{prop} = #{@bytes.next};")
			end
			0.upto(@shorts.size) do
				listen("axobj.#{prop} = #{@shorts.next};")
			end
		end
	end

	def listen(line)
		puts ">> #{line}"
		session = @web_server.accept
		session.gets
		session.write("HTTP/1.1 200 OK\r\n" +
	        "Server: Apache\r\n" +
        	"Content-Type: text/html; charset=ISO-8859-2\r\n" +
    	    "\r\n\r\n" +
	        "<html><meta http-equiv=\"refresh\" content=\"0\"><br>\n" +
        	"[AxRub - Automated ActiveX Fuzzing]<br>[#{@progid}]<br>\n" +
    	    "<br><br>#{line}<br>\n" +
			"<script lang='JavaScript'>\nvar axobj = new ActiveXObject(\"#{@progid}\");\n" +
			"#{line}\n</script>\n</html>")
		session.close
	end

	private

	def ax_properties
		@ax_props = @obj.ole_put_methods.collect! { |d| d.to_s }.uniq
	end

	def ax_methods
		@ax_meths = @obj.ole_methods.select { |m| m.visible? }
	end

	def init_efuzz
		@strings = EFuzz::String.new(1024, 'B')
	    @ints = EFuzz::Int.new
	    @bytes = EFuzz::Byte.new
		@shorts = EFuzz::Short.new
	end
end

## A test harness
if $0 == __FILE__
	ax = AxRub.new(ARGV[0], 'blacklist.txt')
#	ax.blacklist
	ax.launch_ie
	ax.fuzz
end
