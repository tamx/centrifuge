# centrifuge

HTTP のメソッドごとに、接続先を振り分けます。

# 使い方：

% centrifuge -p :10443/ssl host1:80 GET:host2:443/ssl POST:host3:80

とすると、 10443 ポートで SSL で待ち受け、
GET リクエストは host2 へ、
POST リクエストは host3 へ、
その他のリクエストは host1 へリダイレクトします。

この際、 host2 へのアクセスは 443 番ポートで、 SSL を使用します。

# なんの役に立つの？

SSTP サーバーとの振り分けとか、自前のメソッドの定義が楽になります。

SSTP 接続は、ヘッダに SSTP で始まる文字列を送ってきますが、
Windows は最初の１文字、つまり S のみしか最初は送ってこないので、
以下のようになります。

% centrifuge -p :10443/ssl localhost:80 S:****.vpnazure.net:443/ssl

他にも、自前でメソッドを追加して、 443番ポートを節約できます。

% centrifuge -p :10443/ssl localhost:80 STONE:localhost:10022

とすると、 STONE ヘッダを持つ接続は、 localhost の 10022 番へリダイレクトされます。

なお、ヘッダも 10022 番へ送られるので、 stone 等で待ち受ける際には気を付けてください。

ssh と ssl を振り分けるのには、 sslh コマンドを推奨します。
