$(document).ready(function () {

	var $status = $('#status');
	//$status.text("lol");
	//$status.html("lol");

	
	$('form').on('submit', function(){

		var longPoll = setInterval(function () {
			$.get('/checkstatus').then(function (status){
				$status.text(status);
				if (parseInt(status) === 100){
					clearInterval(longPoll);
				}
			});
		
		},500);

	});
	
});