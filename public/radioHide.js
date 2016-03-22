$(document).ready(function () {

	$('div[id^="key_text"]').hide();
	$('div[id^="bar"]').hide();
	$("input[type='checkbox']").on( "click", function() {
	  if($("input[value='check']").is(':checked')) {
		  $('div[id^="key_text"]').show();
		  $('input[id^="key_text_field"]').attr('required','');
	  } else {
		  $('div[id^="key_text"]').hide();
		  $('input[id^="key_text_field"]').removeAttr('required');
	  }
	});
});