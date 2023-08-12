DROP TABLE IF EXISTS to_do;
DROP TABLE IF EXISTS employee;
DROP TABLE IF EXISTS task_status;
CREATE TABLE employee
(
    id varchar(36) not null primary key,
    name varchar(255) not null,
    about varchar(255),
    created timestamp,
    modified timestamp,
    active boolean
);
CREATE TABLE to_do
(
  id varchar(36)  not null , primary key(id),
  description varchar(255) not null,
  created timestamp,
  modified timestamp,
  completed boolean,
  taskstatus varchar(255),
  ownerid varchar(36),
  FOREIGN KEY (ownerid) REFERENCES employee(id)

);
DROP TABLE IF EXISTS task_status;
CREATE TABLE task_status
(
    id varchar(36) not null primary key,
    description varchar(255) not null,
    created timestamp,
    modified timestamp,
    active boolean
);


