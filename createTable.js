var AWS = require("aws-sdk");

AWS.config.update({
	region: "us-east-1",
	endpoint: "http://localhost:8000"
});

var dynamodb = new AWS.DynamoDB();
/*
var params = {
	TableName : "UserTable",
	KeySchema:[
		{AttributeName: "user_id", KeyType: "HASH"}
	],
	AttributeDefinitions:[
		{AttributeName: "user_id", AttributeType: "N"}
	],
	ProvisionedThroughput:{
		ReadCapacityUnits:10,
		WriteCapacityUnits:10
	}
};
*/
/*
var params = {
	TableName : "EmailTable",
	KeySchema:[
		{AttributeName: "email", KeyType: "HASH"}
	],
	AttributeDefinitions:[
		{AttributeName: "email", AttributeType: "S"}
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
*/
/*
var params = {
	TableName : "AtomicCounters",
	KeySchema:[
		{AttributeName: "id", KeyType: "HASH"}
	],
	AttributeDefinitions:[
		{AttributeName: "id", AttributeType: "S"}
	],
	ProvisionedThroughput:{
		ReadCapacityUnits:10,
		WriteCapacityUnits:10
	}
};

*/

var doc = new AWS.DynamoDB.DocumentClient();
var table = "AtomicCounters";
var id = "counter";
var params = {
	TableName: table,
	Item:{
		"id": id,
		"count":0
	}
};

doc.put(params, function(err, data){
	if (err){
		console.log("error: ",JSON.stringify(err,null,2));
	}
	else{
		console.log("Added item:", JSON.stringify(data,null,2));
	}
});


