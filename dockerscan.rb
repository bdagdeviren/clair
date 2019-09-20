require 'docker'
require 'securerandom'
require 'zlib'
require 'archive/tar/minitar'
include Archive::Tar
require 'json'
require 'net/http'
require 'uri'

class Clair
    def initialize(tarname,clairurl,fileserver,fileserverport)
       @tar_file_name = tarname
       @clair_url = clairurl
       @file_server_url = fileserver
       @file_server_port = fileserverport
    end
    def un_tar_file()
        @tar_file_name.chomp(File.extname(@tar_file_name))
        Minitar.unpack(@tar_file_name, File.basename(@tar_file_name, '.*'))
    end
    def post_layer_to_clair()
        file = File.read('./'+File.basename(@tar_file_name, '.*')+'/manifest.json')
        data = JSON.parse(file)

        @layers = []
        parent_layer = ""
        for layer in data[0]['Layers']
            layer['/layer.tar'] = ''
            @layers.push({'id'=> layer,
                            'path'=> @file_server_url+':'+@file_server_port+'/'+File.basename(@tar_file_name, '.*')+'/'+layer+'/layer.tar',
                            'parent'=> parent_layer,
                            'image'=> 'alpine'
                })
            parent_layer = layer
        end

        uri = URI.parse(@clair_url+":6060/v1/layers")
        header = {'Content-Type': 'text/json'}

        for layer in @layers
            clair_layer = {
                Layer: {
                    Name: layer['id'],
                    Path: layer['path'],
                    ParentName: layer['parent'],
                    Format: 'Docker'
                }
            }.to_json
            http = Net::HTTP.new(uri.host, uri.port)
            request = Net::HTTP::Post.new(uri.request_uri, header)
            request.body = clair_layer
            response = http.request(request)   
        end
    end
    def get_layer_vulnerabilities()
        vulnerabilities = Array.new
        for layer in @layers 
            uri = URI.parse(@clair_url+":6060/v1/layers/"+layer['id']+'?features&vulnerabilities')
            http = Net::HTTP.new(uri.host, uri.port)
            response = http.request(Net::HTTP::Get.new(uri.request_uri))

            if response.code == "200"
                result = JSON.parse(response.body)
                result = result['Layer']['Features']
                package = ""
                for i in 0..result.length-1
                    unless result[i]['Vulnerabilities'].nil?
                        vullength = result[i]['Vulnerabilities'].length
                        for j in 0..vullength-1
                            package = result[i]['Name']+":"+result[i]['Version']+":"+result[i]['Vulnerabilities'][j]['Name']+":"+result[i]['Vulnerabilities'][j]['Severity']+":"+result[i]['Vulnerabilities'][j]['FixedBy']
                            unless vulnerabilities.include?(package)
                                vulnerabilities << package
                            end
                        end
                    end
                end
            else
                puts "ERROR!!!"
            end
        end
        puts vulnerabilities
    end
end

clair =Clair.new("./clair.tar","http://localhost","http://localhost","8080")
clair.un_tar_file()
clair.post_layer_to_clair()
clair.get_layer_vulnerabilities()




# splitted_data=data[0]['RepoTags'][0].split(':')
# repo = splitted_data[0]
# tag = splitted_data[1]

# image = Docker::Image.import(tar_file_name)
# image.tag('repo' => repo, 'tag' => tag, force: true)




