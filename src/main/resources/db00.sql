CREATE TABLE IF NOT EXISTS vtb
(
   ver INTEGER default 0
);
CREATE TABLE IF NOT EXISTS atb
(
   aid INTEGER NOT NULL,
   time TIMESTAMP NOT NULL default CURRENT_TIMESTAMP,
   romaji VARCHAR (200) NOT NULL,
   kanji VARCHAR (400) default NULL,
   english VARCHAR (200) default NULL,
   year INTEGER NOT NULL,
   episodes INTEGER NOT NULL,
   last_ep INTEGER NOT NULL,
   type VARCHAR (16) NOT NULL,
   genre VARCHAR (512) NOT NULL,
   img INTEGER default 0,
   PRIMARY KEY (aid)
);
CREATE TABLE IF NOT EXISTS etb
(
   eid INTEGER NOT NULL,
   english VARCHAR (200) NOT NULL,
   kanji VARCHAR (400) default NULL,
   romaji VARCHAR (200) default NULL,
   number VARCHAR (16) NOT NULL,
   time TIMESTAMP NOT NULL default CURRENT_TIMESTAMP,
   PRIMARY KEY (eid)
);
CREATE TABLE IF NOT EXISTS gtb
(
   gid INTEGER NOT NULL,
   time TIMESTAMP NOT NULL default CURRENT_TIMESTAMP,
   name VARCHAR (255) NOT NULL,
   short VARCHAR (255) NOT NULL,
   PRIMARY KEY (gid)
);
CREATE TABLE IF NOT EXISTS ftb
(
   fid INTEGER NOT NULL,
   aid INTEGER NOT NULL,
   eid INTEGER NOT NULL,
   gid INTEGER NOT NULL,
   state INTEGER NOT NULL,
   size BIGINT NOT NULL,
   len INTEGER NOT NULL DEFAULT 0,
   ed2k VARCHAR (32) default NULL,
   md5 VARCHAR (32) default NULL,
   sha1 VARCHAR (40) default NULL,
   crc32 VARCHAR (8) default NULL,
   ripsource VARCHAR (16) default NULL,
   quality VARCHAR (16) default NULL,
   audio VARCHAR (255) default NULL,
   video VARCHAR (16) default NULL,
   resolution VARCHAR (16) default NULL,
   def_name VARCHAR (255) NOT NULL,
   time TIMESTAMP NOT NULL default CURRENT_TIMESTAMP,
   sublang VARCHAR (255) NOT NULL,
   dublang VARCHAR (255) NOT NULL,
   ext VARCHAR (16) DEFAULT '',
   PRIMARY KEY (fid)
);
CREATE TABLE IF NOT EXISTS utb
(
   uid INTEGER NOT NULL,
   name VARCHAR (10) NOT NULL,
   PRIMARY KEY (uid),
   UNIQUE (name)
);
CREATE TABLE IF NOT EXISTS dtb
(
   did INTEGER NOT NULL,
   name VARCHAR (255) NOT NULL,
   PRIMARY KEY (did),
   UNIQUE (name)
);
CREATE TABLE IF NOT EXISTS jtb
(
   orig VARCHAR (255) NOT NULL,
   name VARCHAR (255) NOT NULL,
   did INTEGER NOT NULL,
   fid INTEGER NOT NULL,
   status INTEGER NOT NULL,
   ed2k VARCHAR (32) NOT NULL,
   md5 VARCHAR (32) default NULL,
   sha1 VARCHAR (40) default NULL,
   tth VARCHAR (39) default NULL,
   crc32 VARCHAR (8) default NULL,
   size BIGINT NOT NULL,
   uid INTEGER NOT NULL,
   lid INTEGER NOT NULL,
   time TIMESTAMP NOT NULL default CURRENT_TIMESTAMP,
   avxml TEXT DEFAULT NULL,
   PRIMARY KEY
   (
      size,
      ed2k
   ),
   CONSTRAINT fk_did FOREIGN KEY (did) REFERENCES dtb (did),
   CONSTRAINT fk_fid FOREIGN KEY (fid) REFERENCES ftb (fid),
   CONSTRAINT fk_uid FOREIGN KEY (uid) REFERENCES utb (uid)
);
CREATE INDEX IF NOT EXISTS i_dtb_name ON dtb (name);
CREATE INDEX IF NOT EXISTS i_jtb_name ON jtb (name);
INSERT INTO ftb
(
   fid,
   aid,
   eid,
   gid,
   state,
   size,
   ed2k,
   def_name,
   sublang,
   dublang
)
VALUES
(
   0,
   0,
   0,
   0,
   0,
   0,
   'ed2k',
   '',
   '',
   ''
);
INSERT INTO etb
(
   eid,
   english,
   number
)
VALUES
(
   0,
   '',
   ''
);
INSERT INTO utb (name) VALUES ('default');
INSERT INTO vtb VALUES (6);