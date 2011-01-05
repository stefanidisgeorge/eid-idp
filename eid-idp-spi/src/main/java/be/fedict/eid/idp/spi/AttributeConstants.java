package be.fedict.eid.idp.spi;

/**
 * eID Attribute Constants.
 * <p/>
 * See also: OASIS Identity Metasystem Interoperability Version 1.0
 */
public abstract class AttributeConstants {

    public static final String FIRST_NAME_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";

    public static final String LAST_NAME_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";

    public static final String STREET_ADDRESS_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress";

    public static final String LOCALITY_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality";

    public static final String POSTAL_CODE_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode";

    public static final String COUNTRY_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country";

    public static final String DATE_OF_BIRTH_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth";

    public static final String GENDER_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender";

    public static final String NATIONALITY_CLAIM_TYPE_URI =
            "be:fedict:eid:idp:nationality";

    public static final String PLACE_OF_BIRTH_CLAIM_TYPE_URI =
            "be:fedict:eid:idp:pob";

    public static final String PPID_CLAIM_TYPE_URI =
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier";
}
