How to Work on this app

Keymaster Error:
Navigate to /_km/key
Login as admin
Add the below as a key value pair
spreedly:hackerdojotest = e0cbfb79cc82ba9b5ff21ec2441feee92f535b7e
Note: no = sign in the actual pair

Trick the App into thinking Spreedly posted to it:
Before doing this command
Get the subscriber id from the admin console at /_ah/admin
curl http://localhost:8080/update -v --data-ascii subscriber_ids=1
Note: Don't forget to use the correct port
