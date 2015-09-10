<?php
$secretid = 'your_secretId';
$timestamp = time(); //当前时间
$nonce = rand(100,999999); //随机数

// 1.本地图片，路径前需添加@
$images = array('@img/aa.jpg');
// $images = array('@/Users/xkz_mac/Documents/bb.jpg','@img/aa.jpg');
// 2.图片url
// $images = array('http://image.zzd.sm.cn/18053189379075177102.jpg','http://image.zzd.sm.cn/14984010053067146833.jpg');

$taskUrl = 'http://api.open.tuputech.com/v2/classification/54bcfc31329af61034f7c2f8/54bcfc6c329af61034f7c2fc'; 

// 得到参与签名的参数
$sign_string = $secretid.",".$timestamp.",".$nonce;

//读取私钥，并得到base64格式的签名$signature
$private_key_pem = file_get_contents('pem/rsa_private_key.pem');
$pkeyid = openssl_get_privatekey($private_key_pem);
openssl_sign($sign_string, $signature, $pkeyid, OPENSSL_ALGO_SHA256);
$signature = base64_encode( $signature );

$data = array(
    'secretId' => $secretid,
    'image' => $images,
    'timestamp' => $timestamp,
    'nonce' => $nonce,
    'signature' => $signature
);

//以post方式提交参数
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $taskUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt_custom_postfields($ch, $data);
$output = curl_exec($ch);
curl_close($ch);

//解析返回的数据
$data = json_decode($output, true);
if( $data ){
    $signature = $data['signature'];
    $json = $data['json'];

    $public_key_pem = file_get_contents('pem/open_tuputech_com_public_key.pem');
    //部分用户访问文件权限没有全开，所以建议php用户可以直接读取图普公钥内容
//     $public_key_pem = '-----BEGIN PUBLIC KEY-----
// MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDyZneSY2eGnhKrArxaT6zswVH9
// /EKz+CLD+38kJigWj5UaRB6dDUK9BR6YIv0M9vVQZED2650tVhS3BeX04vEFhThn
// NrJguVPidufFpEh3AgdYDzOQxi06AN+CGzOXPaigTurBxZDIbdU+zmtr6a8bIBBj
// WQ4v2JR/BA6gVHV5TwIDAQAB
// -----END PUBLIC KEY-----';
    $pkeyid2 = openssl_get_publickey($public_key_pem);
    //利用openssl_verify进行验证，结果1表示验证成功，0表示验证失败
    $result = openssl_verify($json, base64_decode($signature), $pkeyid2, "sha256WithRSAEncryption");
    if($result == 1){
        echo '验证成功'.$json;
    }else{
        echo '验证失败'.$json;
    }
}

//该方法的作用是通过$images生成post时的多个image参数
function curl_setopt_custom_postfields($ch, $postfields, $headers = null) {
    $algos = hash_algos();
    $hashAlgo = null;
    foreach ( array('sha1', 'md5') as $preferred ) {
        if ( in_array($preferred, $algos) ) {
            $hashAlgo = $preferred;
            break;
        }
    }
    if ( $hashAlgo === null ) { list($hashAlgo) = $algos; }
    $boundary =
    '----------------------------' .
    substr(hash($hashAlgo, 'cURL-php-multiple-value-same-key-support' . microtime()), 0, 12);

    $body = array();
    $crlf = "\r\n";
    $fields = array();
    foreach ( $postfields as $key => $value ) {
        if ( is_array($value) ) {
            foreach ( $value as $v ) {
                $fields[] = array($key, $v);
            }
        } else {
            $fields[] = array($key, $value);
        }
    }
    foreach ( $fields as $field ) {
        list($key, $value) = $field;
        if ( strpos($value, '@') === 0 ) {
            preg_match('/^@(.*?)$/', $value, $matches);
            list($dummy, $filename) = $matches;
            $body[] = '--' . $boundary;
            $body[] = 'Content-Disposition: form-data; name="' . $key . '"; filename="' . basename($filename) . '"';
            $body[] = 'Content-Type: application/octet-stream';
            $body[] = '';
            $body[] = file_get_contents($filename);
        } else {
            $body[] = '--' . $boundary;
            $body[] = 'Content-Disposition: form-data; name="' . $key . '"';
            $body[] = '';
            $body[] = $value;
        }
    }
    $body[] = '--' . $boundary . '--';
    $body[] = '';
    $contentType = 'multipart/form-data; boundary=' . $boundary;
    $content = join($crlf, $body);
    $contentLength = strlen($content);

    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Content-Length: ' . $contentLength,
    'Expect: 100-continue',
    'Content-Type: ' . $contentType,
    ));

    curl_setopt($ch, CURLOPT_POSTFIELDS, $content);

}
?>