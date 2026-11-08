Случаи:
- запрос без клиентского сертификата
    Error: client didn't provide a certificate
- клиентский сертификат, подписанный другим CA (второй CA)
    remote error: tls: failed to verify certificate: x509: certificate signed by unknown authority
сертификат сервера без SAN;
клиентский сертификат с serverAuth вместо clientAuth;
Go-клиент с InsecureSkipVerify: true против сервера с чужим сертификатом: соединение пройдёт, и это и есть MITM;
просроченный сертификат (выпусти с -days 0 или подмени время).