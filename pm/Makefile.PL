use 5.010000;
use ExtUtils::MakeMaker;

WriteMakefile (
    NAME              => 'NukeDB',
    VERSION      => '0.1',
    PREREQ_PM         => {'DBI' => '1.609',
 			  'DBD::SQLite' =>  '1.29',
			  'Data::Alias' => '1.07',
 			 },
     ABSTRACT          => 'SQLite module for nukessh',
     AUTHOR         => 'Bill Pemberton <wfp5p@virginia.edu>',
    LICENSE      => 'perl',
);
