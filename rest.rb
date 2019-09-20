require 'rubygems'
require 'sinatra/base'

class DockerRest < Sinatra::Base
    get "/" do
        erb :form
    end

    post '/save_image' do
        content_type 'application/octet-stream'
        @filename = params[:file][:filename]
        File.open("./image/#{@filename}.tar", "wb+") do |f|
            f.write(params[:file][:tempfile].read)
        end
    end
end

DockerRest.run! :host => 'localhost', :port => 8082