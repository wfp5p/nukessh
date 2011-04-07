use 5.010000;
use ExtUtils::MakeMaker;

WriteMakefile (
    NAME              => 'NukeDB',
    VERSION      => '0.2',
    PREREQ_PM         => {'DBI' => '1.609',
 			  'DBD::SQLite' =>  '1.29',
 			 },
     ABSTRACT          => 'SQLite module for nukessh',
     AUTHOR         => 'Bill Pemberton <wfp5p@virginia.edu>',
    LICENSE      => 'perl',
);
