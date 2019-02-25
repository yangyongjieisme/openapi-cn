
--------------------------------
install erlang,rabbitmq, install mq service, then copy c:/windos/.erlang.cookie to c:/user/XXX/

rabbitmqctl add_user admin admin
rabbitmqctl set_user_tags admin administrator
rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"



------------------------

redis-server.exe redis.windows.conf
redis-cli.exe -h 127.0.0.1 -p 6379x


do following modifications in redis.windows.conf files :

1 comment bind to 127.0.0.1 to allow connection from all instances
2 Set protected mode to no.
3 requirepass redis2017


when want to set key on cmd, need "auth redis2017"

-----------------------------------

how to run apicn:    mvn spring-boot:run
