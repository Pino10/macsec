require 'sinatra'
require 'active_record'

get '/orders' do
  user = params[:user]
  Order.where("user = '#{user}'").to_json # MACSEC-SQLI
end
