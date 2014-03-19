requires 'perl', '5.010000';
requires 'Socket';

on test => sub 
{
  requires 'Test::More', 0.96;
  requires 'Test::Differences', 0,60;
};
