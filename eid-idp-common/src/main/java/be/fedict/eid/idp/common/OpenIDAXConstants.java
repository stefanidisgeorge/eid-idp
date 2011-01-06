package be.fedict.eid.idp.common;

/**
 * OpenID Attribute Exchange 1.0 Attribute Types returned by eID.
 * <p/>
 * {@see http://www.axschema.org/types/}
 */
public abstract class OpenIDAXConstants {

    public static final String AX_NAME_PERSON_TYPE =
            "http://axschema.org/namePerson";

    public static final String AX_FIRST_NAME_PERSON_TYPE =
            "http://axschema.org/namePerson/first";

    public static final String AX_LAST_NAME_PERSON_TYPE =
            "http://axschema.org/namePerson/last";

    public static final String AX_BIRTHDATE_TYPE =
            "http://axschema.org/birthDate";

    public static final String AX_GENDER_TYPE =
            "http://axschema.org/person/gender";

    public static final String AX_POSTAL_CODE_TYPE =
            "http://axschema.org/contact/postalCode/home";

    public static final String AX_COUNTRY_TYPE =
            "http://axschema.org/contact/country/home";

    public static final String AX_POSTAL_ADDRESS_TYPE =
            "http://axschema.org/contact/postalAddress/home";

    public static final String AX_CITY_TYPE =
            "http://axschema.org/contact/city/home";

    public static final String AX_NATIONALITY_TYPE =
            "http://axschema.org/eid/nationality";

    public static final String AX_PLACE_OF_BIRTH_TYPE =
            "http://axschema.org/eid/pob";
}
