package Responder;

sub new {
	my $class = shift;

	my $self = {
		_env => shift,
		_counter => 0,
		_fd => -1,
	};

	bless $self, $class;

	return $self;
}

sub getline {
	my $self = shift;

	if ($self->{_counter} > 10) {
		return undef;
	}
	elsif ($self->{_counter} == 3) {
		$self->{_counter}++;
		$self->{_fd} = uwsgi::async_connect("81.174.68.52:80");
		return uwsgi::wait_fd_write($self->{_fd}, 3);
	}
	elsif ($self->{_counter} == 4) {
		$self->{_counter}++;
		return "connected to http://projects.unbit.it<br/>";
	}
	elsif ($self->{_counter} == 7) {
		$self->{_counter}++;
		print "suspending the app...\n";
		uwsgi::async_sleep(3);
		uwsgi::suspend();
		print "resumed the app\n";
		return "Suspended and Resumed the app<br/>";
	}
	elsif ($self->{_counter} % 2 == 0) {
		$self->{_counter}++;
		print "sleeping...\n";
		return uwsgi::async_sleep(1);
	}
	else {
		$self->{_counter}++;
		return "Hello World ".$self->{_counter}."<br/>";
	}
}

sub close {
	my $self = shift;
	uwsgi::log("goodbye...\n");
}

1
