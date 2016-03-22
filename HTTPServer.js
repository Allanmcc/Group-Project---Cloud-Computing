//Lets require/import the HTTP module
var http = require('http');
var express = require('express');
var dispatcher = require('httpdispatcher');
var fs = require('fs');
var Busboy = require('busboy');
var path = require('path');
var app = express();
var stream = require('stream');
var crypto = require('crypto'),
	algorithm = 'aes-256-ctr',
	password = 'wtf',
	link_key = 'secretlinkkey123';
var flash = require('connect-flash');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var jwt = require('jsonwebtoken');
var session = require('express-session');
var AWS = require("aws-sdk");
var shortid = require('shortid');
var async = require("async");
AWS.config.update({
	region: "us-east-1",
	endpoint: "http://localhost:8000",
	accessKeyId: "myKeyId",
	secretAccessKey: "secretKey"
});

var dynamodb = new AWS.DynamoDB();


const PORT=8080; 
//Lets define a port we want to listen to
app.use(cookieParser());
app.use(bodyParser.urlencoded());
app.set('hashPhrase', 'some random hash phrase');
app.set('secret', '1234');
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(express.static(__dirname + '/public'));
app.use(session({
	secret: 'session secret'
}));
app.use(flash());
dummy = {
	1: {file_name: "dummy1"},
	2: {file_name: "dummy2"} }

app.get('/test', function(req,res){
	res.render('sol.jade', {
		title: 'pass data test'
	});

});

app.get('/test2', function(req,res){
	 fs.readFile('./banner.html', function(error, content) {
     if (error) {
        serverError(500, content, req, res);
      } else {
        renderHtml(content, req, res);
      }
    });

});

app.get('/test3', function(req,res){
	res.render('frontpage.jade', {
		title: 'pass data test',
		files: dummy,
		selected: "files"
	});

});
app.get("/", function(req,res) {
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/login');
	}
	else{
		res.redirect('/user');
	}
});

app.get("/get", function(req,res) {
	console.log("get here");
	 fs.readFile('./getfile.html', function(error, content) {
     if (error) {
        serverError(500, content, req, res);
      } else {
        renderHtml(content, req, res);
      }
    });
});


app.post("/view_raw", function(req,res){
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	console.log(f)
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/user');
	}
	
	else{
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				var id = decoded.id
				
				res.setHeader('Content-type', 'text/html; filename=' + f);
				fs.createReadStream("./upload/"+id+'/'+f).pipe(res);
			}
		});
	}
});


app.post("/view", function(req,res){
	var f = req.query.f;
	console.log("f: "+f);
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var key = req.body.key;
	console.log("Key: "+key);
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/user');
	}
	
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				
				id = decoded.id;
				var table = 'user_'+id;
				
				var userParams = {
					TableName: table,
					AttributesToGet: [
						"gen_key",
						"secret_key",
						"hash_check"
					],
					Key: {
						"file_name" : {"S": f}

					}
				}
				
				var hash_check;
				var doc = new AWS.DynamoDB;
				doc.getItem(userParams, function(err, data){
					if (err){
						console.log(err);
						res.end("internal error");
						return;
					}
					else{
						console.log(data);
						if (typeof(data.Item) == "undefined"){
							res.redirect('/user');
							console.log("no file found");
							return;
						}
						else{
							if (data.Item.gen_key.S == 't'){
								key = data.Item.secret_key.S;
							}
							hash_check = data.Item.hash_check.S

						}
					}
					var hash = crypto.createHmac('sha256', key).update(app.get('hashPhrase')).digest('hex');
					if (hash == hash_check){
					
						var decrypt = crypto.createDecipher(algorithm, key);
						var filename = f;
						var type = f.substr((~-f.lastIndexOf(".") >>> 0) +2);
						var filePath = ("./upload/"+id+'/'+filename);
						var stat = fs.statSync(filePath);
						console.log("type: "+type);
						
						
						fs.createReadStream("./upload/"+id+'/'+filename).pipe(decrypt).pipe(res);
					}
					else{
						res.end("wrong key");
					
					}
				});
			}
		});
	}	
});


app.post("/download_raw", function(req,res){
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/user');
	}
	
	else{
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				var id = decoded.id;
				res.setHeader('Content-disposition', 'attachment; filename=' + f);
				fs.createReadStream("./upload/"+id+'/'+f).pipe(res);
			}
		});
	}
});

app.post("/delete_file", function(req,res){
	var f = req.query.f;
	var id;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var key = req.body.key;
	
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/user');
	}
	
	else{
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				
				id = decoded.id;
				var table = 'user_'+id;
				
				var userParams = {
					TableName: table,
					Key: {
						"file_name" : f

					}
				}
				var doc = new AWS.DynamoDB.DocumentClient();
				doc.delete(userParams, function(err, data){
				if (err) {
					console.error("Unable to delete item. Error JSON:", JSON.stringify(err, null, 2));
				} else {
					console.log("DeleteItem succeeded:", JSON.stringify(data, null, 2));
				}
				var file = "./upload/"+id+"/"+f;
				fs.unlink(file, function(err){
					if (err){
						console.log(JSON.stringify(err));
					}
				});
				req.flash('prompt', 'true');
				req.flash('message', f+' was successfully deleted.');
				return res.redirect('./user');
				});
			
			}
		});
	}

});


app.post("/quick_view_raw", function(req,res){
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var address = f;
	var key = req.body.key;
	var decipher = crypto.createDecipher(algorithm, link_key);
	var link;
	try{
		link = decipher.update(address, 'hex', 'utf8');
		link += decipher.final('utf8');
	}
	catch(e){
		console.log(e);
		res.end("Invalid address");
		return;
	}
	var content;
	link.replace(/(\r\n|\n|\r)/gm,"");

	content = JSON.parse(link);


	var file_id = content.id;
	var file_name = content.file;


	var table = 'user_'+file_id;
	
	var userParams = {
		TableName: table,
		AttributesToGet: [
			"gen_key",
			"secret_key",
			"hash_check",
			"quickshared"
		],
		Key: {
			"file_name" : {"S": file_name}

		}
	}
	
	var hash_check;
	var doc = new AWS.DynamoDB;
	doc.getItem(userParams, function(err, data){
		if (err){
			console.log(err);
			res.end("internal error");
			return;
		}
		else{
			if (typeof(data.Item) == "undefined"){
				res.redirect('/user');
				console.log("no file found");
				return;
			}
			else{
				if (data.Item.gen_key.S == 't'){
					key = data.Item.secret_key.S;
				}
				hash_check = data.Item.hash_check.S

			}
		}
		console.log(data.Item);
		if (data.Item.quickshared.S == 't'){
		
			fs.createReadStream("./upload/"+file_id+'/'+file_name).pipe(res);

		}
		else{
		
			res.end("Invalid File");
		}
	

	});
		
});

app.post("/quick_download_raw", function(req,res){
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var address = f;
	var key = req.body.key;
	var decipher = crypto.createDecipher(algorithm, link_key);
	var link;
	try{
		link = decipher.update(address, 'hex', 'utf8');
		link += decipher.final('utf8');
	}
	catch(e){
		console.log(e);
		res.end("Invalid address");
		return;
	}
	var content;
	link.replace(/(\r\n|\n|\r)/gm,"");

	content = JSON.parse(link);


	var file_id = content.id;
	var file_name = content.file;


	var table = 'user_'+file_id;
	
	var userParams = {
		TableName: table,
		AttributesToGet: [
			"gen_key",
			"secret_key",
			"hash_check",
			"quickshared"
		],
		Key: {
			"file_name" : {"S": file_name}

		}
	}
	
	var hash_check;
	var doc = new AWS.DynamoDB;
	doc.getItem(userParams, function(err, data){
		if (err){
			console.log(err);
			res.end("internal error");
			return;
		}
		else{
			if (typeof(data.Item) == "undefined"){
				res.redirect('/user');
				console.log("no file found");
				return;
			}
			else{
				if (data.Item.gen_key.S == 't'){
					key = data.Item.secret_key.S;
				}
				hash_check = data.Item.hash_check.S

			}
		}
		console.log(data.Item);
		if (data.Item.quickshared.S == 't'){
		
				
			res.setHeader('Content-disposition', 'attachment; filename=' + file_name);
			fs.createReadStream("./upload/"+file_id+'/'+file_name).pipe(res);

		}
		else{
		
			res.end("Invalid File");
		}
	

	});
		
});


app.post("/quick_view", function(req,res){
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var address = f;
	var key = req.body.key;
	var decipher = crypto.createDecipher(algorithm, link_key);
	var link;
	try{
		link = decipher.update(address, 'hex', 'utf8');
		link += decipher.final('utf8');
	}
	catch(e){
		console.log(e);
		res.end("Invalid address");
		return;
	}
	var content;
	link.replace(/(\r\n|\n|\r)/gm,"");

	content = JSON.parse(link);


	var file_id = content.id;
	var file_name = content.file;


	var table = 'user_'+file_id;
	
	var userParams = {
		TableName: table,
		AttributesToGet: [
			"gen_key",
			"secret_key",
			"hash_check",
			"quickshared"
		],
		Key: {
			"file_name" : {"S": file_name}

		}
	}
	
	var hash_check;
	var doc = new AWS.DynamoDB;
	doc.getItem(userParams, function(err, data){
		if (err){
			console.log(err);
			res.end("internal error");
			return;
		}
		else{
			if (typeof(data.Item) == "undefined"){
				res.redirect('/user');
				console.log("no file found");
				return;
			}
			else{
				if (data.Item.gen_key.S == 't'){
					key = data.Item.secret_key.S;
				}
				hash_check = data.Item.hash_check.S

			}
		}
		console.log(data.Item);
		if (data.Item.quickshared.S == 't'){
			var hash = crypto.createHmac('sha256', key).update(app.get('hashPhrase')).digest('hex');
			if (hash == hash_check){
			
				var decrypt = crypto.createDecipher(algorithm, key);
				fs.createReadStream("./upload/"+file_id+'/'+file_name).pipe(decrypt).pipe(res);
			}
			else{
				res.end("wrong key");
			}
		}
		else{
		
			res.end("Invalid File");
		}
	

	});
		
});


app.post("/quick_download", function(req,res){
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var address = f;
	var key = req.body.key;
	var decipher = crypto.createDecipher(algorithm, link_key);
	var link;
	try{
		link = decipher.update(address, 'hex', 'utf8');
		link += decipher.final('utf8');
	}
	catch(e){
		console.log(e);
		res.end("Invalid address");
		return;
	}
	var content;
	link.replace(/(\r\n|\n|\r)/gm,"");

	content = JSON.parse(link);


	var file_id = content.id;
	var file_name = content.file;


	var table = 'user_'+file_id;
	
	var userParams = {
		TableName: table,
		AttributesToGet: [
			"gen_key",
			"secret_key",
			"hash_check",
			"quickshared"
		],
		Key: {
			"file_name" : {"S": file_name}

		}
	}
	
	var hash_check;
	var doc = new AWS.DynamoDB;
	doc.getItem(userParams, function(err, data){
		if (err){
			console.log(err);
			res.end("internal error");
			return;
		}
		else{
			if (typeof(data.Item) == "undefined"){
				res.redirect('/user');
				console.log("no file found");
				return;
			}
			else{
				if (data.Item.gen_key.S == 't'){
					key = data.Item.secret_key.S;
				}
				hash_check = data.Item.hash_check.S

			}
		}
		console.log(data.Item);
		if (data.Item.quickshared.S == 't'){
			var hash = crypto.createHmac('sha256', key).update(app.get('hashPhrase')).digest('hex');
			if (hash == hash_check){
			
				var decrypt = crypto.createDecipher(algorithm, key);

				
				res.setHeader('Content-disposition', 'attachment; filename=' + file_name);
				fs.createReadStream("./upload/"+file_id+'/'+file_name).pipe(decrypt).pipe(res);
			}
			else{
				res.end("wrong key");
			}
		}
		else{
		
			res.end("Invalid File");
		}
	

	});
		
});



app.post("/download", function(req,res){
	var f = req.query.f;
	console.log("f: "+f);
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var key = req.body.key;
	
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/user');
	}
	
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				
				id = decoded.id;
				var table = 'user_'+id;
				
				var userParams = {
					TableName: table,
					AttributesToGet: [
						"gen_key",
						"secret_key",
						"hash_check"
					],
					Key: {
						"file_name" : {"S": f}

					}
				}
				
				var hash_check;
				var doc = new AWS.DynamoDB;
				doc.getItem(userParams, function(err, data){
					if (err){
						console.log(err);
						res.end("internal error");
						return;
					}
					else{
						console.log(data);
						if (typeof(data.Item) == "undefined"){
							res.redirect('/user');
							console.log("no file found");
							return;
						}
						else{
							if (data.Item.gen_key.S == 't'){
								key = data.Item.secret_key.S;
							}
							hash_check = data.Item.hash_check.S

						}
					}
					var hash = crypto.createHmac('sha256', key).update(app.get('hashPhrase')).digest('hex');
					if (hash == hash_check){
					
						var decrypt = crypto.createDecipher(algorithm, key);
						var filename = f;
						
						res.setHeader('Content-disposition', 'attachment; filename=' + filename);
						fs.createReadStream("./upload/"+id+'/'+filename).pipe(decrypt).pipe(res);
					}
					else{
						res.end("wrong key");
					
					}
				});
			}
		});
	}	
});


app.post("/share_download", function(req,res){
	var f = req.query.f;
	console.log("f: "+f);
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var key = req.body.key;
	
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/user');
	}
	
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				
				id = decoded.id;
				var acc = decoded.account;
				var table = 'share_'+id;
				
				var userParams = {
					TableName: table,
					AttributesToGet: [
						"gen_key",
						"secret_key",
						"hash_check",
						"owner_id"
					],
					Key: {
						"file_name" : {"S": f}

					}
				}
				
				var hash_check;
				var doc = new AWS.DynamoDB;
				doc.getItem(userParams, function(err, data){
					if (err){
						console.log(err);
						res.end("internal error");
						return;
					}
					else{
						console.log(data);
						if (typeof(data.Item) == "undefined"){
							res.redirect('/user');
							console.log("no file found");
							return;
						}
						else{
							var owner_id = data.Item.owner_id.S;
							var params = {
								TableName: "user_"+owner_id,
								AttributesToGet: [
									"sharelist"
								],
								Key: {
									"file_name":{"S":f}
								}
							
							};
							var doc = new AWS.DynamoDB;
							
							doc.getItem(params, function(err, data2){
								var still_shared = false;
								var share_list = data2.Item.sharelist.L;
								share_list.forEach(function (item){
									if (item.S == acc){
										still_shared = true;
									}
								});
								if (still_shared == true){
									if (data.Item.gen_key.S == 't'){
										key = data.Item.secret_key.S;
									}
									hash_check = data.Item.hash_check.S
									
									var hash = crypto.createHmac('sha256', key).update(app.get('hashPhrase')).digest('hex');
									if (hash == hash_check){
									
										var decrypt = crypto.createDecipher(algorithm, key);
										var filename = f;
										
										res.setHeader('Content-disposition', 'attachment; filename=' + filename);
										fs.createReadStream("./upload/"+owner_id+'/'+filename).pipe(decrypt).pipe(res);
									}
									else{
										res.end("wrong key");
									
									}
									
								}
								else{
									res.end("File No Longer Shared");
								}

							});
						}
					
					}
				});
			}
		});
	}	
});

app.get("/shared_file", function(req,res){
	section="share";
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.redirect('/user');
	}
	var token = req.cookies.login_token;
	if (!token){
		res.redirect('/login');
	}
	
	else{
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
			
				var files = {};
				id = decoded.id;
				var acc = decoded.account;
				var error = false;
				var err_msg;
				var gen_key;
				var owner_id;
				var owner_name;
				async.series([
					function(callback){
					
						var doc = new AWS.DynamoDB.DocumentClient();
						
						var params = {
							TableName: 'share_'+id,
							ProjectionExpression: "file_name"
						}
						doc.scan(params, function(err, data){
							if (err){
								console.log("Scan Error: "+JSON.stringify(err, null, 2));
								error = true;
								err_msg = "Failed to load shared file list";
								callback();
							}
							else{
								var i = 1;
								data.Items.forEach(function (f){
									files[i] = f;
									i++;
								});
								callback();
							}
						});
					},
				
					
					
					function(callback){
						var table = 'share_'+id;
				
						var userParams = {
							TableName: table,
							AttributesToGet: [
								"gen_key", "owner_id", "owner_name"
							],
							Key: {
								"file_name" : {"S": f}

							}
						}
						
						var doc = new AWS.DynamoDB;
						doc.getItem(userParams, function(err, data){
							if (err){
								console.log(err);
								res.end("internal error");
								callback();
							}
							else{
								if (typeof(data.Item) == "undefined"){
									res.end("internal error: no file in table");
									callback();
								}
								else{
									gen_key = data.Item.gen_key.S;
									owner_id = data.Item.owner_id.S;
									owner_name = data.Item.owner_name.S;
									callback();
								}
							}
						});	
					},
				
					function(callback){
						var params = {
							TableName: "user_"+owner_id,
							AttributesToGet: [
								"sharelist"
							],
							Key: {
								"file_name":{"S":f}
							}
						
						};
						var doc = new AWS.DynamoDB;
						
						doc.getItem(params, function(err, data){
							if (err){
								console.log(err);
								res.end("internal error");
								callback();
							}
							else{
								if (typeof(data.Item) == "undefined"){
									res.end("internal error: no file in table");
									callback();
								}
								else{
									var still_shared = false;
									var share_list = data.Item.sharelist.L;
									share_list.forEach(function (item){
										
										console.log(f + "   " + item.S);
										if (item.S == acc){
											still_shared = true;
										}
									});
									if (still_shared == true){
										res.render('share.jade', {
											account: acc,
											file_name: f,
											gen: gen_key,
													
											files: files,
											selected: section,
											owner: owner_name
										});
									}
									else{
										res.end("File no longer shared");
									}
									callback();
								}
							}
						});	
					
					}
				]);
				
			
			}
		});
	}

});
app.get("/file", function(req,res){
	var section = req.query.section;
	if (section == '' || section == undefined){
		section = "files"
	}
	var f = req.query.f;
	var gen_key;
	if (f == '' || f == undefined){
		res.redirect('./user');
		return;
	}
	var token = req.cookies.login_token;
	
	if (!token){
		res.redirect('/login');
	}
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				var files = {};
				id = decoded.id;
				var acc = decoded.account;
				doc = new AWS.DynamoDB.DocumentClient();
				
				var params = {
					TableName: 'user_'+id,
					ProjectionExpression: "file_name"
				}
				doc.scan(params, function(err, data){
					if (err){
						console.log("Scan Error: "+JSON.stringify(err, null, 2));
						
					}
					else{
						var i = 1;
						data.Items.forEach(function (f){
							files[i] = f;
							i++;
						});
						var table = 'user_'+id;
				
						var userParams = {
							TableName: table,
							AttributesToGet: [
								"gen_key", "quickshared", "quickshare_link",
							],
							Key: {
								"file_name" : {"S": f}

							}
						}
						
						var doc = new AWS.DynamoDB;
						doc.getItem(userParams, function(err, data){
							if (err){
								console.log(err);
								res.end("internal error");
							}
							else{
								if (typeof(data.Item) == "undefined"){
									res.end("internal error: no file in table");
								}
								else{
									gen_key = data.Item.gen_key.S;
									quickshared = data.Item.quickshared.S;
									quickshare_link = data.Item.quickshare_link.S;
									res.render('file.jade', {
									account: acc,
									file_name: f,
									gen: gen_key,
											
									files: files,
									selected: section,
									quickshared: quickshared,
									quickshare_link: quickshare_link
							
								});
								}
							}
						});	
					}
				});
			}
		});
	}
	
	


});

app.get("/signup", function(req,res) {
	console.log("get here");
	 fs.readFile('./signup.html', function(error, content) {
     if (error) {
        serverError(500, content, req, res);
      } else {
        renderHtml(content, req, res);
      }
    });
});
  


app.get("/quick/:address", function(req,res){

	var address = req.params.address;
	var decipher = crypto.createDecipher(algorithm, link_key);
	var link;
	try{
		link = decipher.update(address, 'hex', 'utf8');
		link += decipher.final('utf8');
	}
	catch(e){
		res.end("Invalid address");
		return;
	}
	var content;
	link.replace(/(\r\n|\n|\r)/gm,"");

	content = JSON.parse(link);


	var file_id = content.id;
	var file_name = content.file;

	var token = req.cookies.login_token;
	
	if (!token){
		quick_render_noToken();
	}
	
	
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				
				quick_render_noToken();
			}
			else{
				var files = {};
				section = "files";
				var id = decoded.id;
				var acc = decoded.account;
				doc = new AWS.DynamoDB.DocumentClient();
				
				var params = {
					TableName: 'user_'+id,
					ProjectionExpression: "file_name"
				}
				doc.scan(params, function(err, data){
					if (err){
						console.log("Scan Error: "+JSON.stringify(err, null, 2));
					}
					else{
						var i = 1;
						data.Items.forEach(function (f){
							files[i] = f;
							i++;
						});
						var table = 'user_'+file_id;
				
						var fileParams = {
							TableName: table,
							AttributesToGet: [
								"gen_key", "quickshared"
							],
							Key: {
								"file_name" : {"S": file_name}

							}
						}
						
						var doc = new AWS.DynamoDB;
						doc.getItem(fileParams, function(err, data){
							if (err){
								console.log(err);
								res.end("internal error");
							}
							else{
								
								if (typeof(data.Item) == "undefined"){
									res.end("internal error: no file in table");
								}
								else{
									
									gen_key = data.Item.gen_key.S;
									quickshared = data.Item.quickshared.S;

									if (quickshared == "t"){
										res.render('quick.jade', {
										account: acc,
										file_name: file_name,
										gen: gen_key,
										address: address,
										files: files,
										selected: section,
										logged_in: "true"
										});
									}
									else{
										res.end('Invalid file');
									}
								}
							}
						});	
					}
				});
			}
		});
	}
	
	function quick_render_noToken(){
		var table = 'user_'+file_id;

		var fileParams = {
			TableName: table,
			AttributesToGet: [
				"gen_key", "quickshared"
			],
			Key: {
				"file_name" : {"S": file_name}

			}
		}
		
		var doc = new AWS.DynamoDB;
		doc.getItem(fileParams, function(err, data){
		
			if (err){
				console.log(err);
				res.end("internal error");
			}
			else{
				
				if (typeof(data.Item) == "undefined"){
					res.end("internal error: no file in table");
				}
				
				
				else{
					
					gen_key = data.Item.gen_key.S;
					quickshared = data.Item.quickshared.S;
					
					if (quickshared == "t"){
					
						res.render('quick.jade', {
							file_name: file_name,
							gen: gen_key,
							logged_in: "false",
							address: address
						});
						
						
					}
					
					else{
						res.end('Invalid file');
					}
				}
				
				
			}
		});	


	}
});


app.get("/sharewith", function(req,res){
	var f = req.query.f;
	var share_username = req.query.u;
	
	console.log("F: "+f);
	console.log("U: "+share_username);
	if (f == '' || f == undefined){
		res.end("Error sharing file");
		return;
	}

	
	var token = req.cookies.login_token;
	if (!token){
		res.end("Error sharing file");
	}
	else{
	
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				return res.end("Error sharing file");
			}
			else{
				id = decoded.id;
				var acc = decoded.account;
				var share_id;
				var share_error = false;
				var err_msg = "";
				var doc = new AWS.DynamoDB.DocumentClient();
				var gen_key;
				var secret_key;
				var hash_check;
				async.series([
					function(callback){
					
						var userParams = {
							TableName: "EmailTable",
							AttributesToGet: [
								"user_id"
							],
							Key: {
								"email" : {"S": share_username}

							}
						};
						var doc2 = new AWS.DynamoDB;
						doc2.getItem(userParams, function(err, data){
							if (err){
								console.log(err);
								share_id = -1;
								share_error = true;
								err_msg = "User not found.";
								callback();
							}
							else{
								if (typeof(data.Item) == "undefined"){
									console.log("here");
									share_id = -1;
									share_error = true;
									err_msg="User not found.";
									callback();
								}
								else{
									console.log("Share ID: "+data.Item.user_id.N);
									share_id = data.Item.user_id.N;
									callback();
								}
							}
						
						});
					
						
					},
					
					function(callback){
						
						if (share_id != -1){
							var params = {
								TableName: "user_"+id,
								Key:{
									file_name: f
								},
								UpdateExpression: "set sharelist = list_append(sharelist, :user)",
								ExpressionAttributeValues:{
									":user":[share_username]
									
								},
								ReturnValues:"UPDATED_NEW"
								};
								
							doc.update(params, function(err, data) {
								if (err) {
									console.log(err);
									err_msg = "Error sharing file.";
									share_error = true;
									callback();
								} 
								else {
									callback();
								}
							});
							
						}
						else{
							callback();
						}
					},
					function(callback){
						if (share_id != -1){
							
				
							var userParams = {
								TableName: "user_"+id,
								AttributesToGet: [
									"gen_key",
									"secret_key",
									"hash_check"
								],
								Key: {
									"file_name" : {"S": f}

								}
							}
							var doc = new AWS.DynamoDB;
							doc.getItem(userParams, function(err, data){
								if (err){
									console.log(err);
									share_error = true;
									err_msg = "Error Sharing File";
									callback();
								}
								else{
									gen_key = data.Item.gen_key.S;
									secret_key = data.Item.secret_key.S;
									hash_check = data.Item.hash_check.S;
									callback();
								}
							});
						}
						else{
							callback()
						}
					
					},
					function(callback){
						if (share_id != -1 & share_error == false){
							var fileParams = {
								TableName: 'share_'+share_id,
								Item:{
									"file_name": f,
									"secret_key":secret_key,
									"gen_key":gen_key,
									"hash_check":hash_check,
									"owner_id":id,
									"owner_name":acc
								}
							};
										
							var doc = new AWS.DynamoDB.DocumentClient();
							doc.put(fileParams, function(err, data){
								if (err){
									console.log("Error upldating user filelist: ",JSON.stringify(err,null,2));
									callback();
								}
								else{
									console.log("Added file:", JSON.stringify(data,null,2));
									callback();
								}
							});
						}
						else{
							callback();
						}
					
					},
					function(callback){
						console.log("made it here");
						if (share_error){
							res.end(err_msg);
						}
						else{
							res.end("Shared to "+share_username);
						}
						callback();
					}
					
				]);
				
			}
		});
	}
});

app.get("/quickshare", function(req,res){
	var f = req.query.f;
	if (f == '' || f == undefined){
		res.end("Error sharing file");
		return;
	}
	var key = req.body.key;
	
	var token = req.cookies.login_token;
	if (!token){
		res.end("Error sharing file");
	}
	
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);

				return res.end("Error sharing file");
			}
			else{
				id = decoded.id;
				var link_data = {id:id,file:f}
				var cipher = crypto.createCipher(algorithm, link_key);
				
				var encrypted_link = cipher.update(JSON.stringify(link_data), 'utf8','hex');
				encrypted_link +=cipher.final('hex');
				var doc = new AWS.DynamoDB.DocumentClient();
				
				var params = {
					TableName: "user_"+id,
					Key:{
						file_name: f
					},
					UpdateExpression: "set quickshared = :t, quickshare_link = :l",
					ExpressionAttributeValues:{
						":l":encrypted_link,
						":t":'t'
					},
					ReturnValues:"UPDATED_NEW"
					
				
				};
				
				doc.update(params, function(err, data) {
					if (err) {
						console.log(err);
						res.end("Error sharing file");
					} else {
						res.end();
					}
				});
				
				
			}
		});
	}

});
 
 
 app.get("/stop_quickshare", function(req,res){
	var f = req.query.f;

	if (f == '' || f == undefined){
		res.end("Error sharing file");
		return;
	}
	var key = req.body.key;
	
	var token = req.cookies.login_token;
	if (!token){
		res.end("Error sharing file");
	}
	
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);

				return res.end("Error sharing file");
			}
			else{
				id = decoded.id;
				
				var doc = new AWS.DynamoDB.DocumentClient();
				
				var params = {
					TableName: "user_"+id,
					Key:{
						file_name: f
					},
					UpdateExpression: "set quickshared = :t, quickshare_link = :l",
					ExpressionAttributeValues:{
						":l":"none",
						":t":'f'
					},
					ReturnValues:"UPDATED_NEW"
					
				
				};
				
				doc.update(params, function(err, data) {
					if (err) {
						console.log(err);
						res.end("Error sharing file");
					} else {
						res.end();
					}
				});
				
				
			}
		});
	}

});
var status = 0;
app.get("/checkstatus", function(req,res){
	
	res.end(status.toString());
	
}); 


app.post("/text_upload", function(req,res){
	var fName = req.body.filename;
	var content = req.body.content;
	var token = req.cookies.login_token;
	var id;
	if (!token){
		res.redirect('/login');
	}	
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				
				id = decoded.id;
				
			}
			
			var s = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
			var key = Array(16).join().split(',').map(function() { return s.charAt(Math.floor(Math.random() * s.length)); }).join('');
			var encrypt = crypto.createCipher(algorithm, key);
			var _dir = './upload/'+'/'+id+'/';
			if (!fs.existsSync(_dir)){
				fs.mkdirSync(_dir);
			}
			var hash = crypto.createHmac('sha256', key).update(app.get('hashPhrase')).digest('hex');
			var gen_key='t';

			var fileParams = {
				TableName: 'user_'+id,
				Item:{
					"file_name": fName,
					"secret_key":key,
					"gen_key":gen_key,
					"hash_check":hash,
					"quickshared":"f",
					"quickshare_link":"none",
					"sharelist":[]
				}
			};
						
			var doc = new AWS.DynamoDB.DocumentClient();
			doc.put(fileParams, function(err, data){
				if (err){
					console.log("Error upldating user filelist: ",JSON.stringify(err,null,2));
				}
				else{
					console.log("Added file:", JSON.stringify(data,null,2));
				}
			});
			var contentStream = new stream.Readable();
			contentStream._read = function noop() {};
			contentStream.push(content);
			contentStream.push(null);
			
			fstream = fs.createWriteStream(_dir+fName);
			contentStream.pipe(encrypt).pipe(fstream);
			fstream.on("close", function(){
				res.redirect("./user");
			});
		});
	}
});
app.post("/upload", function(req,res){

	var token = req.cookies.login_token;
	var key;
	var fName;
	var id = '';
	
	if (!token){
		res.redirect('/login');
	}
	else{
		
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				
				id = decoded.id;
				
				
			}
		
		});

		var gen_key = 't';
		var s = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		var fstream;
		var bb = new Busboy({ headers: req.headers });
		var progress = 0;
		var total = req.headers['content-length'];

		var encrypt;

		bb.on('file', function (fieldname, file, filename, encoding, mimetype){
			if (key == "" | typeof(key) == "undefined"){
				
				key = Array(16).join().split(',').map(function() { return s.charAt(Math.floor(Math.random() * s.length)); }).join('');
			}
			console.log("Key: "+key);
			
			encrypt = crypto.createCipher(algorithm, key);
			if (filename == ''){
				res.redirect('/user');
				return;
			}
			fName = filename;
			var _dir = './upload/'+'/'+id+'/';
			if (!fs.existsSync(_dir)){
				fs.mkdirSync(_dir);
			}
			console.log("Uploading: "+filename);
			var hash = crypto.createHmac('sha256', key).update(app.get('hashPhrase')).digest('hex');
			console.log("hash: "+hash);
			if (gen_key){
				var fileParams = {
					TableName: 'user_'+id,
					Item:{
						"file_name": fName,
						"secret_key":key,
						"gen_key":gen_key,
						"hash_check":hash,
						"quickshared":"f",
						"quickshare_link":"none",
						"sharelist":[]
					}
				};
			}
			else{
				var fileParams = {
					TableName: 'user_'+id,
					Item:{
						"file_name": fName,
						"gen_key":gen_key,
						"hash_check":hash
					}
				};
			
			}
			
			var doc = new AWS.DynamoDB.DocumentClient();
			doc.put(fileParams, function(err, data){
				if (err){
					console.log("Error upldating user filelist: ",JSON.stringify(err,null,2));
				}
				else{
					console.log("Added file:", JSON.stringify(data,null,2));
				}
			});
				
			
			
			
			file.on('data', function(data){
				progress += data.length;
				var perc = parseInt( (progress/total)*100);
				status = perc;
				console.log(status);
			});
			
			fstream = fs.createWriteStream(_dir+fName);
			file.pipe(encrypt).pipe(fstream);
			
		});
		
		bb.on('field', function(fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) {
			if (fieldname == 'key'){
				if (!(gen_key == 't')){
					key = val;
				}
			}
			if (fieldname == 'checkbox'){
				console.log("checkbox: "+val);
				if (val == 'check'){
					gen_key = 'f';

				}
				
				
				
			}
		});
		bb.on('finish', function(){
			console.log("Upload Finished");
		
			res.redirect('/user');
		});

		req.pipe(bb);

		req.on("close", function(err){
			fstream.end();
			fs.unlink('./upload/'+id+'/'+fName);
		
		});
		
	}
});




app.get('/upload_text', function(req,res){
	var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.cookies.login_token;
	if (token){
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				var acc = decoded.account;
				res.render('upload_text.jade', 
					{account: acc});
			}
		});
	}
	else{
		res.redirect('./login');
	}
});

app.get('/upload_file', function(req,res){
	var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.cookies.login_token;
	if (token){
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				var acc = decoded.account;
				res.render('upload_file2.jade', 
					{account: acc});
			}
		});
	}
	else{
		res.redirect('./login');
	}
});

app.get('/encrypt_file', function(req,res){
	var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.cookies.login_token;
	if (token){
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
			res.render('encrypt_file.jade');
			}
		});
	}
	else{
		res.redirect('./login');
	}
});


app.get('/user', function(req,res){
	var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.cookies.login_token;
	var section = req.query.section;
	if (section == '' || section == undefined){
		section = "files"
	}
	if (token){
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				var id = decoded.id;
				var acc = decoded.account;
				if (section == "files"){
					doc = new AWS.DynamoDB.DocumentClient();
					var files = '';
					var params = {
						TableName: 'user_'+id,
						ProjectionExpression: "file_name"
					}
					doc.scan(params, function(err, data){
						if (err){
							console.log("Scan Error: "+JSON.stringify(err, null, 2));
							res.render('user.jade', {
								id: id,
								files: ''
							});
						}
						else{
							files = {};
							var i = 1;
							data.Items.forEach(function (f){
								files[i] = f;

								i++;
							});

							res.render('user.jade', {
								account: acc,
								id: id,
								files: files,
								selected: section,
								prompt: req.flash('prompt'),
								message: req.flash('message')
							});
						}

					});
				}
				else if (section == "more"){
					files = dummy = {
						1: {file_name: "FAQ"},
						2: {file_name: "Other"} 
					}

					res.render('user.jade', {
								account: acc,
								id: id,
								files: files,
								selected: section,
								prompt: req.flash('prompt'),
								message: req.flash('message')
					});
				}
				else if (section == "share"){
					doc = new AWS.DynamoDB.DocumentClient();
					var files = '';
					var params = {
						TableName: 'share_'+id,
						ProjectionExpression: "file_name"
					}
					doc.scan(params, function(err, data){
						if (err){
							console.log("Scan Error: "+JSON.stringify(err, null, 2));
							res.render('user.jade', {
								id: id,
								files: ''
							});
						}
						else{
							files = {};
							var i = 1;
							data.Items.forEach(function (f){
								files[i] = f;

								i++;
							});

							res.render('user.jade', {
								account: acc,
								id: id,
								files: files,
								selected: section,
								prompt: req.flash('prompt'),
								message: req.flash('message')
							});
						}

					});
				}
			}
		
		});
	}
	else{
		res.redirect('./login');
	}

});

app.get('/logout', function(req,res){
	res.clearCookie('login_token');
	res.redirect("./user")

});

app.get('/login', function(req,res){
	var token = req.cookies.login_token;
	
	if (token){
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				res.render('login_page.jade',
					{title: "Login"});
			}
			else{
				res.redirect('./user');
			}
		});
	}
	else{
		res.render('login_page.jade',
			{title: "Login",
			error: req.flash('error'),
			message: req.flash('message')});
	}

});


app.post('/login_request', function(req,res){
	var email_given = req.body.email;
	var password_given = req.body.password;
	var email;
	var password;
	var id;
	var emailTable = "EmailTable";
	var userTable = "UserTable";
	
	if (email_given.length <= 0){
		res.end("invalid email");
		return;
	}
	if (password_given.length <= 0){
		res.end("invalid password");
		return;
	}
	
	var emailParams = {
		TableName: "EmailTable",
		AttributesToGet: [
			"user_id"
		],
		Key: {
			"email" : {"S": email_given}

		}
	};
	
	
	var doc = new AWS.DynamoDB;
	
	doc.getItem(emailParams, function(err, data){
	
		if (err){
			console.log(err);
			req.flash('error', 'true');
			req.flash('message', 'Internal Error')
			res.redirect('/login');
		}
		else{
			if (typeof(data.Item) == "undefined"){
				//Account not found
				req.flash('error', 'true');
				req.flash('message', 'Account Not Found')
				res.redirect('/login');
			}
			else{
				id = data.Item.user_id.N;
				
				var userParams = {
					TableName: userTable,
					AttributesToGet: [
						"password", "salt"
					],
					Key: {
						"user_id" : {"N": id}

					}
				}
				
				doc.getItem(userParams, function(err, data2){
					if (err){
						console.log(err);
						res.end("internal error");
					}
					else{
						if (typeof(data2.Item) == "undefined"){
							req.flash('error', 'true');
							req.flash('message', 'Internal Error')
							res.redirect('/login');
						}
						else{
						
							
							var salt=data2.Item.salt.S;

							var given_hash = crypto.createHash('sha512').update(password_given+salt).digest("base64");
		
							var hash = data2.Item.password.S;
							
							
							if (given_hash == hash){
								var sig =  {"id": id,
											"account": email_given};
								var token = jwt.sign(sig, app.get('secret'),{
									expiresIn: "24h"
								});
							
								/*res.json({
									success:true,
									message: 'login success',
									token: token
								});*/
								res.clearCookie('login_token');
								
								res.cookie('login_token', token, {maxAge:1000*60*60*24, httpOnly: true});
								
								
								res.redirect('./user');
							}
							else{
								req.flash('error', 'true');
								req.flash('message', 'Incorrect Password')
								res.redirect('/login');
							}
						}
					}
				
				
				});
			}
			
		}
	});

	
	
	
	
});


app.post('/signup_request', function(req, res){

	var email = req.body.email;
	
	var password = req.body.password;
	var id_count;
	var doc = new AWS.DynamoDB.DocumentClient();
	var table = "UserTable";
	var countTable = "AtomicCounters";
	
	var id = "counter";

	var counterParams = {
		TableName: countTable,
		Key:{
			"id": id
		},
		UpdateExpression: "SET #count = #count + :val",
		ExpressionAttributeNames:{
			"#count":"count"
		},
		ExpressionAttributeValues:{
			":val": 1
		},
		ReturnValues: "UPDATED_NEW"
		
	};

	var checkEmailParams = {
		TableName: "EmailTable",
		KeyConditionExpression: "email = :email",
		ExpressionAttributeValues:{
			":email":email
		}
	}
	var params = {
		TableName: countTable,
		KeyConditionExpression: "id = :counter",
		ExpressionAttributeValues:{
			":counter":"counter"
		}
	
	};
	
	doc.query(checkEmailParams, function(err, data){
		if (err){
			console.error("Check Email Error: ",JSON.stringify(err, null, 2));
		}
		else{
			if (data.Items.length > 0){
				req.flash('error', 'true');
				req.flash('message', 'Email Already Exists')
				res.redirect('/login');
			}
			else{
				addUser();
			}
		}
	
	});
	
	function addUser(){

		doc.query(params, function(err, data){
			if (err){
				req.flash('error', 'true');
				req.flash('message', 'Internal Error')
				res.redirect('/login');
			}
			else{
				data.Items.forEach(function(item){
					var salt=crypto.randomBytes(128).toString('base64'); 
					var pass_to_hash = password+salt;
					var hash = crypto.createHash('sha512').update(pass_to_hash).digest("base64");
					var user_id=item.count;
					var UserParams = {
						TableName: "UserTable",
						Item:{
							"user_id": user_id,
							"email":email,
							"password":hash,
							"salt":salt
						}
					};
					var EmailParams = {
						TableName: "EmailTable",
						Item:{
							"email": email,
							"user_id":user_id,
						}
					};
					doc.put(EmailParams, function(err, data){
					
						if (err){
							console.log("put email error: ",JSON.stringify(err,null,2));
						}
						else{
							console.log("Added email:", JSON.stringify(data,null,2));
						}
					});
					
					doc.put(UserParams, function(err, data){
						if (err){
							console.log("put user error: ",JSON.stringify(err,null,2));
						}
						else{
							console.log("Added user:", JSON.stringify(data,null,2));
								doc.update(counterParams, function(err, data){
								if (err){
									console.error("Error on count: ", JSON.stringify(err, null, 2));
								}
								else{
									console.log("count: ",JSON.stringify(data,null,2));
									req.flash('error', 'alert');
									req.flash('message', 'Account Created')
									res.redirect('/login');
								}
								
							});
		
							
						}
					});
					var params = {
						TableName : "user_"+user_id.toString(),
						KeySchema:[
							{AttributeName: "file_name", KeyType: "HASH"}
						],
						AttributeDefinitions:[
							{AttributeName: "file_name", AttributeType: "S"}
						],
						ProvisionedThroughput:{
							ReadCapacityUnits:10,
							WriteCapacityUnits:10
						}
					};
					dynamodb.createTable(params, function(err, data) {
						if (err) {
							console.error("Unable to create table. Error JSON:", JSON.stringify(err, null, 2));
						} else {
							params = {
								TableName : "share_"+user_id.toString(),
								KeySchema:[
									{AttributeName:"file_name", KeyType: "HASH"}
								],
								AttributeDefinitions:[
									{AttributeName:"file_name", AttributeType: "S"}
								],
								ProvisionedThroughput:{
									ReadCapacityUnits: 10,
									WriteCapacityUnits:10
								}
							};
							dynamodb.createTable(params, function(err, data){
								if (err){
									console.log(err)
								}
								else{
									console.log("created share table");
								}
							});
						}
							console.log("Created table. Table description JSON:", JSON.stringify(data, null, 2));
						
					});

				});
				
			}
		});
		
	}
});

//Display Functions

  var serverError = function(code, content, req, res) {
    res.writeHead(code, {'Content-Type': 'text/plain'});
    res.end(content);
  }

  var renderHtml = function(content, req, res) {
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(content, 'utf-8');
  }

  
 app.listen(PORT, function(){
	console.log("Server is running");
 });