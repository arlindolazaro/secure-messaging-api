package com.securemessaging.dto;

public class CertificateRequest {
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String locality;
    private String province; 
    private String country;
    private Integer validDays;
    private Integer validYears;

    // Getters e Setters
    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    public void setOrganizationalUnit(String organizationalUnit) {
        this.organizationalUnit = organizationalUnit;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    // ✅ MUDADO: getState() para getProvince()
    public String getProvince() {
        return province;
    }

    // ✅ MUDADO: setState() para setProvince()
    public void setProvince(String province) {
        this.province = province;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public Integer getValidDays() {
        return validDays;
    }

    public void setValidDays(Integer validDays) {
        this.validDays = validDays;
    }

    public Integer getValidYears() {
        return validYears;
    }

    public void setValidYears(Integer validYears) {
        this.validYears = validYears;
    }
}