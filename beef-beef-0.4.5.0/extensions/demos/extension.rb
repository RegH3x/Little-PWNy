#
# Copyright (c) 2006-2014 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - http://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
module BeEF
module Extension
module Demos
  
  extend BeEF::API::Extension
  
  @short_name = 'demos'
  
  @full_name = 'demonstrations'
  
  @description = 'list of demonstration pages for beef'
  
end
end
end

require 'extensions/demos/api'
