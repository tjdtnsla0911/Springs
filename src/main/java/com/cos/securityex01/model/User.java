package com.cos.securityex01.model;



import java.sql.Timestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.hibernate.annotations.CreationTimestamp;

import lombok.Data;

@Data
@Entity
public class User {
@Id//primarykey
@GeneratedValue(strategy = GenerationType.IDENTITY) //primary키에 auto거는거임
private int id;
private String username;
private String password;
private String email;
private String Rore;
@CreationTimestamp
private Timestamp crateDate;


}
