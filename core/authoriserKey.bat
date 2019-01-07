rem usage  authoriserKey <service> <region> <stage> <key> <algorithm>

aws ssm put-parameter --region %2 --name /%1/%3/Authoriser/JWTKey --value %4 --type SecureString --overwrite
aws ssm put-parameter --region %2 --name /%1/%3/Authoriser/Algorithm --value %5 --type SecureString --overwrite