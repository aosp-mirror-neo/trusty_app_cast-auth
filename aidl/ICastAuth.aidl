interface ICastAuth {
    const String PORT = "com.android.trusty.cast_auth";

    @TrustyPayload(response=false)
    void ProvisionKey();

    @TrustyPayload()
    void SignHash();
}
