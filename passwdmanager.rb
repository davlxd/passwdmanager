#! /usr/bin/env ruby
# -*- encoding: utf-8 -*-

# Generate and store password
# Copyright (C) 2012-2013  lxd <i@lxd.me>
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'rubygems'
begin
  require 'readline'
  require 'highline/import'
  require 'clipboard'
rescue LoadError
  puts "#{$!}"
  exit 1
end
require 'openssl'
require 'digest/sha1'
require 'base64' 



$DEFAULT_PASSWD_LEN = 15
$DEFAULT_PASSWD_COMB = 7

$COMB_DIGIT = 4
$COMB_CHAR = 2
$COMB_SPECIAL_CHAR = 1
$PID_FILE = '.' + File.basename($0, '.rb') + '.pid'



class PasswdTable
  #TODO remove it and print 
  attr_reader :main_pw
  attr_accessor :passwd_records
  
  def initialize(str = '')
    @main_pw = ''
    @passwd_records = []
    $COL_ORDER = [:name, :usrname, :passwd, :update_ts]
    from_s str unless str.empty?
  end

  def size
    @passwd_records.length
  end
  
  
  def to_s
    ret = @main_pw + "\n"
    @passwd_records.each do |row|
      $COL_ORDER.each { |col| ret += "#{row[col]}\t" }
      ret += "\n"
    end
    ret
  end
  

  def print_passwd_records
    printf("    %-20s %-20s %s\n", 'name', 'uername', 'last modified time')
    @passwd_records.each_with_index do |row, idx|
      printf("[%d] %-20s %-20s %s\n",
             idx, row[:name], row[:usrname], Time.at(Integer(row[:update_ts])))
    end
  end
  
  
  def from_s str
    raise ArgumentError if  str.empty?
    
    arr = str.split "\n" 
    @main_pw = arr.shift
    arr.each do |row|
      row_arr = row.split "\t"
      return false if row_arr.length != 4
      @passwd_records << Hash[$COL_ORDER.zip row_arr]
    end
  end

  def main_pw= new_main_pw
    @main_pw = new_main_pw
    unload(EnDecypt.encrypt(self.main_pw, self.to_s))
  end


  def push_to_bottom idx
    @passwd_records << @passwd_records.delete_at(idx)
    unload(EnDecypt.encrypt(self.main_pw, self.to_s))
  end


  def get_passwd_str idx
    passwd_str = @passwd_records[idx][:passwd]
    push_to_bottom idx
    passwd_str
  end

  def add new_record
    raise ArgumentError if new_record.empty?
    
    new_record[:update_ts] = Time.now.to_i.to_s
    @passwd_records << new_record
    unload(EnDecypt.encrypt(self.main_pw, self.to_s))
  end
  

  def update idx, new_record
    raise ArgumentError unless (0...size).include? idx
    raise ArgumentError if new_record.empty?

    new_record[:update_ts] = Time.now.to_i.to_s
    new_record.each_pair do |k, v|
      if k == :passwd
        @passwd_records[idx][k] << "\s" << v unless v.nil? or v.empty?
      else
        @passwd_records[idx][k] = v unless v.nil? or v.empty?
      end
    end
    unload(EnDecypt.encrypt(self.main_pw, self.to_s))
  end
  

  def del idx
    raise ArgumentError unless (0...size).include? idx
    @passwd_records.delete_at(idx)
    unload(EnDecypt.encrypt(self.main_pw, self.to_s))
  end
  
end



class EnDecypt
  def self.encrypt key, txt
    key = iv = Digest::SHA1.hexdigest key
    cipher = OpenSSL::Cipher.new 'AES-128-CFB'
    cipher.encrypt
    cipher.key = key[0...16]
    cipher.iv = iv[0...16]
    Base64.encode64(cipher.update(txt) + cipher.final)
  end

  def self.decrypt key, ctxt64
    key = iv = Digest::SHA1.hexdigest key
    decipher = OpenSSL::Cipher.new 'AES-128-CFB'
    decipher.decrypt
    decipher.key = key[0...16]
    decipher.iv = iv[0...16]
    txt = decipher.update(Base64.decode64(ctxt64) + decipher.final)
    if txt.ascii_only? then txt else false end
  end
end



def load
  pos = DATA.pos
  ret = DATA.read
  DATA.pos = pos
  ret
end



def unload ciphertext
  File.open(__FILE__, 'r+') do |f|
    f.each do |l|
      if l =~ /^__END__/
        f.write ciphertext
      end
    end
  end
end



def die exit_num = 0
  if not File.exists?($PID_FILE)
    puts 'Something goes wrong!'
  else
    File.delete($PID_FILE)
  end
  puts 'Bye~'
  exit
end



def generate_passwd len, combination
  digits = '0123456789'
  chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
  special_chars = '~`!@#$%^&*()-=_+,.<>/?;:\'"|{}[]'

  material = []
  material << digits if combination & $COMB_DIGIT != 0
  material << chars if combination & $COMB_CHAR != 0
  material << special_chars if combination & $COMB_SPECIAL_CHAR != 0

  passwd = []
  (0...len).each do |i|
    one_third = material[rand(material.length)]
    target = one_third[rand(one_third.length)]
    passwd << target
  end

  passwd.join()
end



def update_main_passwd pwtable
  main_pw = ask('Input new main passwd >> ') {|q| q.echo=false}
  return :abort if main_pw.empty?

  main_pw1 = ask('Do it again as usual >> ') {|q| q.echo=false}
  return :abort if main_pw1.empty? or main_pw != main_pw1

  pwtable.main_pw = main_pw
end



def pull *pwtable
  pwtable = pwtable[0]
  puts 'Not implemented yet'
end



def push *pwtable
  pwtable = pwtable[0]
  puts 'Not implemented yet'
end



class CommandDispatcher
  @@command_prefix = {
    '?' => ['Print this', :print_help],
    'pull' => ['Request from remote server', :pull],
    'push' => ['Push new password to remote server', :push],
    'q' => ['Quit', :die],
    'um'=> ['Update main password', :update_main_passwd],
    'n' => ['Create new entry', :create_new_entry],
    'd' => ['Delete a entry', :delete_entry],
    'u' => ['Update password', :update_passwd],
    'c' => ['Copy to clipboard', :copy_to_clipboard],
    's' => ['Show passwd on terminal', :show_to_terminal]
  }
  
  
  def initialize()
  end

  
  def exec_command(cmd, pwtable)
    cmd_arr = cmd.split("\s")
    unless @@command_prefix.keys.include?(cmd_arr[0])
      raise ArgumentError, 'Command not found'
    end
    send @@command_prefix[cmd_arr[0]][1], pwtable, *cmd_arr[1...cmd_arr.length]
  end

  
  def print_help(*)
      @@command_prefix.each {|k, v| puts "#{k}\t#{v[0]}"}
  end
  

  def validate_index idx_str, idx_ceiling
    raise ArgumentError, "Give me the index!" if idx_str.nil?
    
    begin
      idx_int = Integer idx_str
    rescue
      raise ArgumentError, "#{idx_str} must be an integer!"
    end
    
    unless (0...idx_ceiling).include? idx_int
      raise ArgumentError, "between (0...#{idx_ceiling})!"
    end
    idx_int
  end
  

  def do_collect_entry_info promt, must_int = false
    begin
      while value = Readline.readline(promt, false)
        break unless value =~ /\s/
        puts 'No spaces'
        next
        if must_int
          break if (Integer passwd_len rescue nil) or passwd_len.empty?
          puts 'Integer please'
          next
        end
      end
    rescue SystemExit, Interrupt
      die
    end
    die if value.nil?
    value
  end
  

  def collect_entry_info
    name = do_collect_entry_info 'Entry name > '
    usrname = do_collect_entry_info 'Username > '
    passwd = do_collect_entry_info 'Password > '
    
    return {name: name, usrname: usrname, passwd: passwd}  unless passwd.empty?

    
    passwd_len = do_collect_entry_info("Passwd length "\
                                       "(default #{$DEFAULT_PASSWD_LEN}) ", true)

    if passwd_len.empty?
      passwd_len = $DEFAULT_PASSWD_LEN
    else
      passwd_len = Integer passwd_len
    end
    
    passwd_comb = do_collect_entry_info("Password combination "\
                                        "(default #{$DEFAULT_PASSWD_COMB}): \n"\
                                        "  #{$COMB_DIGIT} - digit - [0-9]\n"\
                                        "  #{$COMB_CHAR} - charactar [a-zA-Z]\n"\
                                        "  #{$COMB_SPECIAL_CHAR} - "\
                                        "special charactor [\p\]\n> ", false)

    if passwd_comb.empty?
      passwd_comb = $DEFAULT_PASSWD_COMB
    else
      passwd_comb = Integer passwd_comb
    end
    
    {name: name, usrname: usrname, passwd_len: passwd_len, passwd_comb: passwd_comb}
  end
  

  def create_new_entry *pwtable
    pwtable = pwtable[0]
    puts
    puts 'Create a new entry'
    
    hash = collect_entry_info

    if hash.keys.include? :passwd_len
      passwd = generate_passwd hash[:passwd_len], hash[:passwd_comb]
      hash.delete :passwd_len
      hash.delete :passwd_comb
      hash[:passwd] = passwd
    end

    pwtable.add hash
  end


  def delete_entry pwtable, *index
    index = index[0]
    index = validate_index index, pwtable.size
    puts "\nRemove entry #{index}"

    begin
      ret = Readline.readline('Are you sure? (y/n)', false)
    rescue SystemExit, Interrupt
      die
    end
    return if ret.nil? or ret.empty?
    
    pwtable.del index if ret.downcase.start_with? 'y'
  end


  def update_passwd pwtable, *index
    index = index[0]
    index = validate_index index, pwtable.size
    puts "\nUpdate entry #{index}"
    
    hash = collect_entry_info
    if hash.keys.include? :passwd_len
      passwd = generate_passwd hash[:passwd_len], hash[:passwd_comb]
      hash.delete :passwd_len
      hash.delete :passwd_comb
      hash[:passwd] = passwd
    end

    pwtable.update index, hash
  end

  
  def copy_to_clipboard pwtable, *index
    index = index[0]
    index = validate_index index, pwtable.size

    Clipboard.copy pwtable.get_passwd_str(index).split("\s")[-1]
    begin
      Readline.readline('# Press Any key to clear password from clipbord #', false)
    rescue SystemExit, Interrupt
    end
    Clipboard.clear
  end
  

  def show_to_terminal pwtable, *index
		puts
    index = index[0]
    index = validate_index index, pwtable.size

    puts pwtable.get_passwd_str index
    begin
      Readline.readline('# Press Any key to clear password from screen #', false)
    rescue SystemExit, Interrupt
    end
    9999.times { puts "\n" }
  end
  
end



# In memory of http://www.imdb.com/title/tt1276104/
def looper(pwtable)
  cmd_dispr = CommandDispatcher.new
  
  loop do
    puts
    pwtable.print_passwd_records
    begin
      cmd = Readline.readline('> ', true)
    rescue SystemExit, Interrupt
      die
    end
    die if cmd.nil?

    begin
      cmd_dispr.exec_command(cmd, pwtable)
    rescue ArgumentError
      puts "#{$!}"
    end
  end
  
end



def first_time_use
  puts 'No CipherText found, '\
  'maybe it\'s your first time run this script or pretend to do so, '\
  'anyway create your main pasword '

  pwtable = PasswdTable.new

  begin
    ret = update_main_passwd(pwtable)
  rescue SystemExit, Interrupt
    die
  end
 
  if ret == :abort
    die 1
  else
    unload(EnDecypt.encrypt(pwtable.main_pw, pwtable.to_s))
  end
  pwtable
end


def not_first_time_use
  begin
    main_pw = ask('Input main passwd >> ') {|q| q.echo=false}
  rescue SystemExit, Interrupt
    die
  end
  
  if main_pw.nil? or main_pw.empty? or not txt = EnDecypt.decrypt(main_pw, load)
    die 1
  end
  PasswdTable.new txt
end



def command_exists? cmd
  ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
    return true if File.exists? "#{path}#{File::SEPARATOR}#{cmd}"
  end
  false
end

def main
  if File.exists?($PID_FILE)
    puts 'Already a process is running.'
    exit 0
  else
    begin
      File.open($PID_FILE, 'w') { |f| f.write($$) }
    rescue Exceptoin
      puts 'Something goes wrong when create PID file!'
      puts "#{$!}"
      exit 1
    end
  end
  
  puts <<LICENSE
License under GNU GPL version 3 <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
LICENSE
  puts
  puts RUBY_COPYRIGHT
  puts RUBY_DESCRIPTION
  puts 'Author: lxd <i@lxd.me>'
  puts
  puts 'xclip not installed!' unless command_exists? 'xclip'

  ciphertext = load
  if ciphertext.empty? or ciphertext =~ /^\s$/
    pwtable = first_time_use
  else
    pwtable = not_first_time_use
  end

  looper pwtable
end



if __FILE__ == $0
  main
end



__END__

