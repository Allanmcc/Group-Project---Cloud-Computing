$(document).ready(function () {

	$('div[id^="key"]').hide();

	$("input[type='radio']").on( "click", function() {
	  if($("input[value='no']").is(':checked')) {
		  $('div[id^="key"]').show();
	  } else {
		  $('div[id^="key"]').hide();
	  }
	});
});