$(document).ready(function () {
	
	var $status = $('#status');

	$('form').on('submit', function(){
		alert("test")
		var longPoll = setInterval(function () {
			$.get('/checkstatus').then(function (status){
				$status.text(status);
				$('.progress-bar').attr('aria-valuenow',status);
				if (parseInt(status) === 100){
					clearInterval(longPoll);
				}
			});
		
		},500);

	});
	
});