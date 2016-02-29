//Lets require/import the HTTP module
var http = require('http');
var express = require('express');
var dispatcher = require('httpdispatcher');
var fs = require('fs');
var Busboy = require('busboy');
var path = require('path');
var app = express();
var crypto = require('crypto'),
	algorithm = 'aes-256-ctr',
	password = 'wtf';

var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var jwt = require('jsonwebtoken');

var AWS = require("aws-sdk");

AWS.config.update({
	region: "us-east-1",
	endpoint: "http://localhost:8000",
	accessKeyId: "myKeyId",
	secretAccessKey: "secretKey"
});

var dynamodb = new AWS.DynamoDB();


//Lets define a port we want to listen to
const PORT=8080; 
app.use(cookieParser());
app.use(bodyParser.urlencoded());
app.set('hashPhrase', 'some random hash phrase');
app.set('secret', '1234');
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(express.static(__dirname + '/public'));


app.get('/test', function(req,res){
	res.render('sol.jade', {
		title: 'pass data test',
		users: dummy
	});

});
app.get("/", function(req,res) {
	res.redirect('/user');
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
				var id = decoded
				res.setHeader('Content-disposition', 'attachment; filename=' + f);
				fs.createReadStream("./upload/"+id+'/'+f).pipe(res);
			}
		});
	}
});
app.post("/download", function(req,res){
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
				
				id = decoded;
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


app.get("/file", function(req,res){
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
				
				id = decoded;
				var table = 'user_'+id;
				
				var userParams = {
					TableName: table,
					AttributesToGet: [
						"gen_key"
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
						console.log(data);
						if (typeof(data.Item) == "undefined"){
							res.end("internal error: no file in table");
						}
						else{
							gen_key = data.Item.gen_key.S;
							res.render('file.jade', {
	
							file_name: f,
							gen: gen_key
						});
						}
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
  

 
var status = 0;
app.get("/checkstatus", function(req,res){
	res.end(status.toString());
	
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
				
				id = decoded;
				
				
			}
		
		});

		var gen_key = 'f';
		var s = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		var fstream;
		var bb = new Busboy({ headers: req.headers });
		var progress = 0;
		var total = req.headers['content-length'];

		var encrypt;

		bb.on('file', function (fieldname, file, filename, encoding, mimetype){
			
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
						"hash_check":hash
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
			if (fieldname == 'radio'){
				if (val == 'yes'){
					gen_key = 't';
					key = Array(16).join().split(',').map(function() { return s.charAt(Math.floor(Math.random() * s.length)); }).join('');

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

app.post('/getfile', function(req, res){

	var decrypt = crypto.createDecipher(algorithm, password);
	var filename = req.body.filename;
	
	res.setHeader('Content-disposition', 'attachment; filename=' + filename);
	fs.createReadStream("./upload/"+filename).pipe(decrypt).pipe(res);
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
			res.render('upload_file2.jade');
			}
		});
	}
	else{
		res.redirect('./login');
	}
});
app.get('/user', function(req,res){
	var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.cookies.login_token;
	
	if (token){
		jwt.verify(token, app.get('secret'), function(err, decoded){
			if (err){
				console.log(err);
				res.clearCookie('login_token');
				return res.redirect('./login');
			}
			else{
				console.log(decoded);
				var id = decoded;
				doc = new AWS.DynamoDB.DocumentClient();
				var files = '';
				var params = {
					TableName: 'user_'+id,
					ProjectionExpression: "secret_key, file_name"
				}
				doc.scan(params, function(err, data){
					if (err){
						console.log("Scan Error: "+JSON.stringify(err, null, 2));
						res.render('user.jade', {
							id: decoded,
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
							id: decoded,
							files: files
						});
					}
				
				
				});

				

				
			}
		
		});
	}
	else{
		res.redirect('./login');
	}

});

app.get('/logout', function(req,res){
	res.clearCookie('login_token');
	res.end("logged out");

});

app.get('/login', function(req,res){
	fs.readFile('./login.html', function(error, content) {
	 if (error) {
		serverError(500, content, req, res);
	  } else {
		renderHtml(content, req, res);
	  }
	});

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
		TableName: emailTable,
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
			res.end("internal error");
		}
		else{
			if (typeof(data.Item) == "undefined"){
				res.end("Account Not Found");
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
							res.end("internal error: no user_id in UserTable");
						}
						else{
						
							
							var salt=data2.Item.salt.S;

							var given_hash = crypto.createHash('sha512').update(password_given+salt).digest("base64");
		
							var hash = data2.Item.password.S;
							
							
							if (given_hash == hash){
								var token = jwt.sign(id, app.get('secret'),{
									expiresIn: "24h"
								});
							
								/*res.json({
									success:true,
									message: 'login success',
									token: token
								});*/
								res.clearCookie('login_token');
								
								res.cookie('login_token', token, {maxAge:1000*60*60*24, httpOnly: true});
								console.log('cookie created');
								
								//res.redirect('./user?token='+token);
								res.redirect('./user');
							}
							else{
								
								res.end("incorrect password");
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
				res.end("email already exists");
			}
			else{
				addUser();
			}
		}
	
	});
	
	function addUser(){

		doc.query(params, function(err, data){
			if (err){
				console.error("Error: ", JSON.stringify(err, null, 2));
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
						console.log("lol");
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
							console.log("Created table. Table description JSON:", JSON.stringify(data, null, 2));
						}
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