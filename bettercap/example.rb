class Example < BetterCap::Proxy::TCP::Module
  meta(
    'Name'        => 'Example',
    'Description' => 'Example TCP proxy module.',
    'Version'     => '1.0.0',
    'Author'      => "Simone 'evilsocket' Margaritelli",
    'License'     => 'GPL3'
  )
  
  # Received when the victim is sending data to the upstream server.
  def on_data( event )
    # You can access the request data being sent using the event object:
    #
    #   event.data.gsub!( 'SOMETHING', 'ELSE' )
    #
    BetterCap::Logger.raw "\n#{BetterCap::StreamLogger.hexdump( event.data )}\n"
  end
  # Received when the upstream server is sending a response to the victim.
  def on_response( event )
    # You can access the response data being received using the event object:
    #
    #   event.data.gsub!( 'SOMETHING', 'ELSE' )
    #
    BetterCap::Logger.raw "\n#{BetterCap::StreamLogger.hexdump( event.data )}\n"
  end
end
