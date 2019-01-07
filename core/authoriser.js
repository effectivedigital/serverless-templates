const jwt  = require('jsonwebtoken');
//const util = require('util');     //Enable this for debugging

const AWS  = require('aws-sdk');
const ssm  = new AWS.SSM();

exports.handler =  function(event, context, callback) {
    //Check to see if there is a token
    if (!event.authorizationToken) {
        return callback(null, "Error: Missing token"); 
    }

    //If the token is supplied using the authentication section of Postman, it pre-pends "Bearer" to the token.
    //As the token is a string, this text needs to be removed for it to be considered valid
    var token = event.authorizationToken.replace("Bearer ", '').replace("bearer ", '');

    //Set up the request to retrieve the token encryption key
    var req = {
        Names: [process.env.key],
        WithDecryption: process.env.IsEncrypted == "false" ? false : true
      };

    //Retrieve the encryption key from the Stored Parameter
    ssm.getParameters(req, function(err, data) {
        //There was some sort of error retrieving the encryption key. Automatically deny the access to the API
        if (err) {
            console.log("Error: " + err.name + " Message: " + err.message);
            return callback(null, generatePolicy('user', 'Deny', event.methodArn));
        }

        //Key has been retrieved. Next is to verify the token. The verify will confirm that the token is valid prior to decoding it.
        jwt.verify(token, data.Parameters[0].Value,{ algorithms: [process.env.Algorithm] }, function(err, decoded) {
            var policyType = 'Deny';
            
            //Check if there was an error during the verify process. If so, auto Deny access to the API
            if (err) {
                console.log("Error: " + err.name + " Message: " + err.message);
                policyType = 'Deny';
            } else {
                //This line is to be used for debug only
                //console.log("The decoded token: " + util.inspect(decoded, false, null, true));

                //This is where the check of the field to determine access occurs.
                switch (decoded[process.env.CheckField]) {
                    case 'true':
                        policyType = 'Allow';
                        break;
                    default:
                        policyType = 'Deny';
                        break;
                } 
            }

            //Based on the check, either Allow or Deny access to the API
            return callback(null, generatePolicy('user', policyType, event.methodArn));
        });
    });
};

// Helper function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};
    
    //This generates a valid autherisation response for the API resource requested
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; 
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    
    // // Optional output with custom properties of the String, Number or Boolean type.
    // authResponse.context = {
    //     "stringKey": "stringval",
    //     "numberKey": 123,
    //     "booleanKey": true
    // };
    return authResponse;
}