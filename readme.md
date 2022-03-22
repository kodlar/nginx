terminal olarak mobaxterm windows için indirebilirsiniz

http://nginx.org/en/download.html adresine gidiyoruz. Mainline version altında changes linki yanındaki nginx-1.xx linki kopyalayıp ubuntu üzerinde
indiriyoruz. İndirmek için curl ya da wget ile linki çağırabilirsiniz

- indirdiğimiz dizindeki dosyayı tar -zxvf dosya.tar komutunu çalıştırarak açıyoruz
- açtığımız dosyanın içine cd /path/ olarak içine giriyoruz
- girdiğimiz dizinde terminal ekranına komut satırı olarak ./configure diyoruz ve bir hata ile karşılaşıyoruz. Mesajda C compiler cc is not found
- Ubuntuda bu hatayı çözmek için "apt-get install build-essential" diyerek ihtiyacımız olan dosyaları indirebiliriz.
- Daha sonra tekrar ./configure diye build ediyoruz. Build sonunda  şu şekilde bir hata mesajı daha karşımıza çıkıyor

./configure: error: the HTTP rewrite module requires the PCRE library.
You can either disable the module by using --without-http_rewrite_module
option, or install the PCRE library into the system, or build the PCRE library
statically from the source with nginx by using --with-pcre=<path> option.

Ubuntuda ilgili kütüphaneleri bulmak için pcre yani regex kütüphanesi gzip çalıştırmak için zlib1g ssl desteği içinde libssl-dev
apt-get install libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev
bu komutu çalıştırdıktan sonra tekrar ./configure diyerek bir çok hatanın gittiğini göreceğiz
Bu durumda kodumuz compile edilmeye hazır vaziyette. Ancak eklememiz gereken custom modülleri daha eklemedik. Bu arada akla şöyle bir şey gelebilir. Neden biz apt-get install nginx diyerek nginx kütüphanesini kurmadık. Sebebi basit bu default kurulumda custom modüle eklenemiyor. O yüzden kendi build edeceğimiz custom modül kurulabilir bir ngix oluşturuyoruz. 
 Şimdi ./configure --help diye komut çalıştırırsak hangi nginx custom modüllerini görüntüleyebiliriz. Ancak bu gösterimde modülleri ne işe yaradığını anlatan bir açıklama bilgisine sahip değiliz. Bunun ne manaya geldiğini daha iyi anlamak için http://nginx.org/en/docs/configure.html linkine tıkladığınızda nginx modüllerinin ne olduğunu okuyabilirsiniz

Nginx modülleri 2 çeşittir. Bundle modülü ve 3rd parthy modülü Bundle modüller burada nginx üzerinde gelirken 3rd party modülleri indirilip compile edilmesi gereken modüllerdir. Bundle modülü üzerinde zip,geolocation ve ssl örnek gösterilebilir


Buna göre kendi özelleştirilmiş konfigurasyonumuzu yazalım
./configure  --sbin-path=/usr/bin/nginx  --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-pcre --pid-path=/var/run/nginx.pid --with-http_ssl_module 

Bu konfigürasyon kontrolü hatasız geçildiğinde "make" komutu ile konfigürasyonu derleyebiliriz
make
 
Bu işlem bittikten sonra derlenen kodu makineye yüklemek için "make install" diyerek kurulumu gerçekleştiriyoruz

make install

mesela yaptığımız konfigürasyon kodunun doğru yerde olduğundan emin olmak için ls -l /etc/nginx diyerek dosyaları kontrol edebiliriz.

Artık nginx executable dosyası hazır olduğu için sunucu üzerinde nginx versiyonunu kontrol edebiliriz

nginx -V 

Burada hem versiyonu hemde yapmış olduğumuz konfigürasyonu görebiliriz

Nginx sunucusunu çalıştırmak için  nginx yazıp entera basmamız yeterlidir. 
nginx

Nginx çalıştırdığınzda şu şekilde bir hata alıyorsanız benim gibi windows makine üzerinde iis kurulu ise önce iis lokalde durdurun. Sonra tekrar komutu çalıştırın böylece 80 portu boş kalacaktır.
 [emerg] bind() to 0.0.0.0:80 failed (13: Permission denied)

Eğer bir hata yoksa çalışan prosesi görmek için 
ps aux | grep nginx 
çalıştırabiliriz. proces komutunun kısaltması ps au -> all user x -> booteable processleri dahil et ve greplediğimiz terimi getir diyoruz

Şimdi nginx'imizi servis olarak ayağa kaldıralım. Böylece devamlılığını sağlamış olacağız

nginx -s stop diyerek durdurma sinyali gönderiyoruz
diğer komutları görmek için nginx -h diyebiliriz

Nginx durdurduktan sonra
https://www.nginx.com/resources/wiki/start/topics/examples/systemd/ bu adresteki konfigürasyonu oluşturacağız

bizden öncelikle dosyanın bu yolda olması gerektiğini söylüyor /lib/systemd/system/nginx.service O yüzden

touch /lib/systemd/system/nginx.service diyerek dosyayı oluşturuyoruz
nano /lib/systemd/system/nginx.service ile dosyayı açıyoruz

[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/bin/nginx -t
ExecStart=/usr/bin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target

dosyayı kaydettikten sonra systemctl start nginx diyebilirsiniz

Eğer makine bir sebepten restart olursa ve nginx'in servis olarak ayağa kalkması için
systemctl enable nginx komutunu çalıştırmanız gerekiyor.

wsl ile bağlandığınız ubuntuya winscp ile dosya atmak için bu linkte yazılanları yapmanız yeterli https://www.virtualizationhowto.com/2021/01/copy-files-to-windows-subsystem-for-linux-wsl2-with-ssh/

nginx -s stop diyerek durdurduk
wsl ubuntu altında root üzerinde /sites/demo diye bir klasör açtık üzerine dosyalarımızı yolladık. Dosyalarımızı attıktan sonra /etc/nginx/nginx.conf dosyası için düzenleme yaptık.

events {}


http {

    server {
        listen 80;
        server_name localhost;

        root /sites/demo;
    }

}

Eğer wsl bir sürüm olmasaydı servisi sytemctl reload nginx komutu ile nginx'i stop edip downtime yapmadan devam ettirebilirdik. Burada bir hata olursa nginx eski konfigürasyonu ile işleme devam edecektir. systemctl restart nginx diyerek işlem yaparsanız nginx'i durdurup eğer konfigürasyonda
bir hata olursa nginx başlatmayacaktır.

wsl ile ip bulmak için powershell açıp wsl hostname -i demeniz yeterli bu ip adresini tarayıcınıza yapıştırıp çağırırsanız nginx sunucunuz gelecek

http {
    include  mime.types;

    server {
        listen 80;
        server_name 127.0.1.1 localhost;

        root /sites/demo;
        #prefix match herhangi bir kelime greet ile başlıyorsa bu adres cevap vermeye devam edecektir
        location /greet {
            return 200 'Hello from nginx "/greet" location !';
        }
    }

}


Eğer location adresleri belirli sembollerle başlarsa mesela 

1- Exact match =uri
2- Preferential Prefix match ^~uri
3- Regex match ~*uri insensitive case
4- Regex match ~uri case sensitive match
5- Prefix match neyle başlıyorsa ona yönlendiriyor


Nginx variables için http://nginx.org/en/docs/varindex.html bu adrese bakılabilir. 2 tip variable var, 1-build-in variables ve diğer configuration variables


Belirli bir path altında acces_log kapatmak için location altına access_log off; yeterlidir. Eğer burada acces_log'u takip etmek için özel bir yol verirsek access logu o yoldaki loga yazacaktır. Böylece nginx altındaki genel loga o path ile ilgili log yazılmayacaktır. Ancak her ikisinede yazılsın dersek access_log çoğaltıp her iki logun yolunu verirsek tüm logpathlere log atılır


Directivelerin çeşitleri

events {}

######################
# (1) Array Directive
######################
# Can be specified multiple times without overriding a previous setting
# Gets inherited by all child contexts
# Child context can override inheritance by re-declaring directive
access_log /var/log/nginx/access.log;
access_log /var/log/nginx/custom.log.gz custom_format;

http {

  # Include statement - non directive
  include mime.types;

  server {
    listen 80;
    server_name site1.com;

    # Inherits access_log from parent context (1)
  }

  server {
    listen 80;
    server_name site2.com;

    #########################
    # (2) Standard Directive
    #########################
    # Can only be declared once. A second declaration overrides the first
    # Gets inherited by all child contexts
    # Child context can override inheritance by re-declaring directive
    root /sites/site2;

    # Completely overrides inheritance from (1)
    access_log off;

    location /images {

      # Uses root directive inherited from (2)
      try_files $uri /stock.png;
    }

    location /secret {
      #######################
      # (3) Action Directive
      #######################
      # Invokes an action such as a rewrite or redirect
      # Inheritance does not apply as the request is either stopped (redirect/response) or re-evaluated (rewrite)
      return 403 "You do not have permission to view this.";
    }
  }
}



Deneme amaçlı php yüklüyoruz
apt-get install php-fpm daha sonra aşağıdaki konfigürasyon yapılabilir. Görüleceği üzere index directive'i geldi sitenin önce index.php'ye bakması index.php bulamazsa index.html'e gitmesi gerektiği söyleniyor.
Burada location php kısmı reverse proxy mantığı ile çalışıp gelen işlemi fastcgi.con üzerinden php servise gönderiyor. Kendi yüklediğiniz php'nin fpm.sock versiyonu için find üzerinden fpm.sock dosyasının
yerini aratıp ilgili satırı güncelleyebilirsiniz.

user www-data;

events {}

http {

  include mime.types;

  server {

    listen 80;
    server_name 167.99.93.26;

    root /sites/demo;

    index index.php index.html;

    location / {
      try_files $uri $uri/ =404;
    }

    location ~\.php$ {
      # Pass php requests to the php-fpm service (fastcgi)
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;
    }

  }
}

Bir başka directive worker_processes Bu directive bize nginx gelen requesti ne kadar hızlı cevaplayabileceği donanım bazlı ayarı gösterir. Burada nginx 1 worker process 1 cpu mimarisi üzerinde çalışır. Bu noktada doğru ayarı
yapabilmek adına makinanız üzerindeki işlemci sayısını bulup ona göre bir değer girebiliriz. Eğer 1  işlemcili makinede worke process sayısını 2 diye girerseniz %50 performans ile çalışacktır, düzgün çalışabilmesi için 1 girmek
yeterlidir. İşlemci sayınızı görmek için nproc komutunu çalıştırıp bulabilirsiniz. Ayrıca worker_processes sayısı yazmak yerine auto derseniz nginx makinanınızın konfigürasyonuna uygun worker sayısını çalıştıracaktır

Bir başka directive workerın max alabileceği connection sayısıdır. Bunu bulmak için ulimit -n komutu size connection sayısını gösterir. Bu sayıyıda events altına şu şekilde belirtiyoruz

events {
     worker_connections  1024;
}

Bu noktada nginx concurrent olarak worker_connections x worker_processes = max bağlantı sayısını döndürecektir.

Bir başka ayar statik dosyalar bağlantılarla ilgili ayarların tanımlanması

worker_processes  auto;

events {
     worker_connections  1024;
}


http {
    include  mime.types;
    #Buffer gelen tcp isteğindeki datayı ram'e ram yetmediğinde diske yazar
    #Bu yazma işlemi ile ilgili ayarlar aşağıda ram/disk yazma şekli 10kilobyte olarak yaz
    #diyoruz bunu daha da arttırabiliriz diğer ayarda gönderilen post 8 megabyte geçmesin diyoruz
    # Buffer size for POST submissions
    client_body_buffer_size 10K;
    client_max_body_size 8m;
    #header size ayarlıyoruz
    # Buffer size for Headers
    client_header_buffer_size 1k;
    #bağlantı durumunu kontrol edilmesi
    # Max time to receive client headers/body
    client_body_timeout 12;
    client_header_timeout 12;
    # açık bağlantıyı ne kadar sürdüreyim
    # Max time to keep a connection open for
    keepalive_timeout 15;
   
    # Max time for the client accept/receive a response
    send_timeout 10;
    
    # Skip buffering for static files
    sendfile on;

    # Optimise sendfile packets
    tcp_nopush on;

    server {
        listen 80;
        server_name 127.0.1.1 localhost;

        root /sites/demo;


        set $weekend 'No';

        #check if weekend  not equal operator tilda
        if ( $date_local ~ 'Saturday|Sunday') {
            set $weekend 'Yes';
        }

        location /is_weekend {
            return 200 $weekend;
        }
        #yönlendirme
        location /logo {
            return 307 /thumb.png;
        }
        

        #try_files $uri /friendly404;

        #location /friendly404 {
        #    return 404 "that is reason why you are here";
        #}

        #rewrite more consume resources than redirect
        rewrite ^/user/\w+ /greet;
        location /greet {
            return 200 "selamlar gençler";
        }
       #rewrite again with capture group and handle as $1
        rewrite ^/member/(\w+) /test/$1;

        location = /test/john {
            return 200  "Hello john";
        }
        #check static API key
        #if ( $arg_apikey != 1234 ) {
        #    return 401 "Incorrect API key";
        #}
        #variables kullanımına örnek
        #location = /inspect {
           #return 200 "$host\n$uri\n$args";     
           #return 200 "Name: $arg_name";     
        #}  

        #prefix match herhangi bir kelime greet ile başlıyorsa bu adres cevap vermeye devam edecektir
        #location /greet {
        #    return 200 'Hello from nginx "/greet" location !';
        #}

        #exact match herhangi bir kelime greet ile başlıyorsa bu adres cevap vermeye devam edecektir
        #location = /greet {
        #    return 200 'Hello from nginx "/greet" location Exact Match !';
        #}
        
        #regex match tilda character case sensitive if you upper any character then 404 will return
        #location ~ /greet[0-9] {
        #    return 200 'Hello from nginx "/greet" location Regex Match !';
        #}

        #Preferential Prefix Match 
        location ^~ /Greet2 {
            return 200 'Hello from nginx "/greet" location preferential Match !';
        }

        #regex match insensitive shoul use * character 
        location ~* /greet[0-9] {
            return 200 'Hello from nginx "/greet" location insensitive Match !';
        }
    }

}

Nginx üzerinde dinamik modüller istek bazında yüklenir, statik modüller her daim yüklenir
Dinamik modül yüklemek için ilk yapılacak işlem
nginx -V çalıştırılır
Konfigürasyon argümanları satırı kopyalanır.
--sbin-path=/usr/bin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-pcre --pid-path=/var/run/nginx.pid --with-http_ssl_module

daha sonra dinamik modülleri listelemek için
nginx dizini içinde ./configure --help | grep dynamic

  --with-http_xslt_module=dynamic    enable dynamic ngx_http_xslt_module
  --with-http_image_filter_module=dynamic
                                     enable dynamic ngx_http_image_filter_module
  --with-http_geoip_module=dynamic   enable dynamic ngx_http_geoip_module
  --with-http_perl_module=dynamic    enable dynamic ngx_http_perl_module
  --with-mail=dynamic                enable dynamic POP3/IMAP4/SMTP proxy module
  --with-stream=dynamic              enable dynamic TCP/UDP proxy module
  --with-stream_geoip_module=dynamic enable dynamic ngx_stream_geoip_module
  --add-dynamic-module=PATH          enable dynamic external module
  --with-compat                      dynamic modules compatibility


./configure --sbin-path=/usr/bin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-pcre --pid-path=/var/run/nginx.pid --with-http_ssl_module --with-http_image_filter_module=dynamic --modules-path=/etc/nginx/modules

bu konfigürasyonu çalıştırınca 

./configure: error: the HTTP image filter module requires the GD library.
You can either do not enable the module or install the libraries.

GD library bulunamadığı için hata alacaktır.

 hatayı gidermek için "apt-get install libgd-dev" yüklememiz gerekiyor, linux için resim işleme kütüphanesi
 
 Bu kütüphaneyi yükledikten sonra tekrar komutumuzu çalıştıryoruz
 
 ./configure --sbin-path=/usr/bin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-pcre --pid-path=/var/run/nginx.pid --with-http_ssl_module --with-http_image_filter_module=dynamic --modules-path=/etc/nginx/modules
 
 işlem bittikten sonra konfigürasyonumuzu make komutu ile derliyoruz.
 
 Compile edilmiş kodu mevcut konfigürasyona yüklemek için make install komutunu çalıştırıyoruz
 
 Görüldüğü üzere mevcut nginx konfigürasyon dosyasında hiçbir değişiklik olmadı. Bunu anlamak için nginx -V yapmamız yeterlidir.
 
#dinamik imaj modülü yüklemek için ngix.conf içine bu kodu ekliyoruz
load_module modules/ngx_http_image_filter_module.so bu satır hata verirse load_module /etc/nginx/modules/ngx_http_image_filter_module.so; şeklinde deneyin

gzip ile statik dosya tiplerini sıkıştırıp performansı arttırabiliriz
gzip on;
#sıkıştırma oranı 
gzip_comp_level 3;
gzip_types text/css;
gzip_types text/javascript;

curl -I http://localhost/style.css
curl -I -H "Accept-Encoding:gzip, deflate" http://localhost/style.css

curl http://localhost/style.css > style.css
curl -H "Accept-Encoding:gzip, deflate" http://localhost/style.css > style.min.css
download edip karşılaştırırsak aradaki boyut farkını görebiliriz

Cacheleme için aşağıdaki değerlere bakacak olursak ilk satırda cache path level ile cacheleme düzeyini keys_zone ile cache grubu 100mb olacak şekilde eğer cache 60 dakika kimse gelmezse ilgili cache sil diyoruz
cache key parametresi ile cache keyimizi oluşturuyoruz, bu cachekey md5 ile hashlaniyor
 # Configure microcache (fastcgi)
  fastcgi_cache_path /tmp/nginx_cache levels=1:2 keys_zone=ZONE_1:100m inactive=60m;
  fastcgi_cache_key "$scheme$request_method$host$request_uri";
  #bu headerda HIT görürsek cachelenmiş MISS görürsek cachesiz geliyor demektir
  add_header X-Cache $upstream_cache_status;

  ilgili location altında
  location ~\.php$ {
            

                # Enable cache
                # Yukarıdaki zone alanı
                fastcgi_cache ZONE_1;
                # Hangi response tipi ne kadar süre cachelenecek yukarıdaki inactive süresi # ile aynı olmalı
                fastcgi_cache_valid 200 60m;
                fastcgi_cache_bypass $no_cache;
                fastcgi_no_cache $no_cache;
        }

Şimdi test edebilmek için apache benchmark tool kullanacağız Yüklemek için aşağıdaki kodu çalıştırıyoruz

apt-get install apache2-utils ile yüklüyoruz

ab diyip komutu çalıştırırsak opsiyonları listeleriz

ab -n 100 -c 10 http://127.0.1.1/

burada 100 request 10 kullanıcı tarafından olsun diyoruz


HTTP2 modülü yükleme

nginx -V
diyerek configürasyon pathimizi aldık

--sbin-path=/usr/bin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-pcre --pid-path=/var/run/nginx.pid --with-http_ssl_module --with-http_image_filter_module=dynamic --modules-path=/etc/nginx/modules

diğer modülleri görmek için

./configure --help | grep http_v2 çalıştırıyoruz
  --with-http_v2_module              enable ngx_http_v2_module


./configure --sbin-path=/usr/bin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --with-pcre --pid-path=/var/run/nginx.pid --with-http_ssl_module --with-http_image_filter_module=dynamic --modules-path=/etc/nginx/modules --with-http_v2_module

konfigürasyon check bitince tekrar 

make  --yani compile etmesi için çağırıyoruz

make install -- compile edilmiş konfigürasyonu yüklemek için çalıştırıyoruz

nginx servisi restart edelim

 sonra ilgili site için development amaçlı ssl sertifikası oluşturuyoruz
nginx konfig dosyasının bulunduğu dizinde ssl dosyası oluşturuyoruz

openssl req -x509 -days 365 -nodes -newkey rsa:2048 -keyout /etc/nginx/ssl/self.key -out /etc/nginx/ssl/self.crt

key oluşturma sorularına öylesine cevap veriyoruz

Country Name (2 letter code) [AU]:AU
State or Province Name (full name) [Some-State]:WCAPE
Locality Name (eg, city) []:İstanbul
Organization Name (eg, company) [Internet Widgits Pty Ltd]:bizimcompany
Organizational Unit Name (eg, section) []:dev
Common Name (e.g. server FQDN or YOUR name) []:ogan keskiner
Email Address []:ogankeskiner@gmail.com

-rw-r--r-- 1 root root 1.5K Mar 21 22:14 self.crt (SERTİFİKA)
-rw------- 1 root root 1.7K Mar 21 22:13 self.key (PRIVATE KEY)

konfigürasyona ilgili directiveleri ekliyoruz

listen 80;
listen 443 ssl http2;

ssl_certificate /etc/nginx/ssl/self.crt;
ssl_certificate_key /etc/nginx/ssl/self.key;

ve aşağıdaki komutla çağırıyoruz 
curl -Ik  https://127.0.1.1
curl -I https://127.0.1.1 --insecure


Server Push

apt-get install nghttp2-client
n parametresi to discard responses we are only testing not saving to disk
y ignore self-signed certificate
s print the response statistics
nghttp -nys https://127.0.1.1/index.html

a all the assets in the file

nghttp -nysa https://127.0.1.1/index.html

location = /index.html {
      http2_push /style.css;
      http2_push /thumb.png;
    }

SSL'i daha güvenli hale getirme için yapılan işlemler

dhparam oluşturmak için aşağıdaki kodu çalıştırıyoruz
openssl dhparam -out /etc/nginx/ssl/dhparam-2048.pem 2048
diğer açıklamalar config dosyasında

RateLimit
Sitemize veya apimize gelen istekleri saldırılara karşı korumak için alınan bir tedbirdir
Test etmek için siege kullanacağız
apt-get install siege ile programı yüklüyoruz
-v verbose login
-r 2 run 2 tests
-c 5 concurrent 5 connection 
siege -v -r 2 -c 5 https://127.0.1.1/thumb.png

config dosyasına rate limit koyuyoruz
limit_req_zone $request_uri zone=MYZONE:10m rate=1r/s;
direktiften sonra belirli bir url adresine Myzone alanında saniyede 1 istek alsın diye sınırlama getiriyoruz