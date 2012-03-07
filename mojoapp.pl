use Mojolicious::Lite;

# /
get '/' => 'index';

# /*
get '/:groovy' => sub {
    my $self = shift;
    $self->render_text($self->param('groovy'), layout => 'funky');
};

app->start('psgi');
__DATA__

@@ index.html.ep
% layout 'funky';
Yea baby!

@@ layouts/funky.html.ep
<!doctype html><html>
    <head><title>Funky!</title></head>
    <body><%= content %></body>
</html>
