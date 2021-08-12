CREATE OR REPLACE PACKAGE pck_pbx AS
-- --------------------------------------------------------------------------
-- Name         : PCK_PBXssss
-- Author       : 
-- Description  : Package for
-- Requirements : Package for Hosted PBX
-- License      : The content of this document can only be derived rights against Belize Telemedia Limited
--                if they are supported by duly signed documents. The information may be confidential and 
--                only for use by the addressee (s). If you have this document unjustly in your possession,
--                you are requested to destroy it. It is not allowed to revise this document or parts thereof,
--                copying or use outside of its context.
-- Amendments   :
--   When         Who                   What
--   ===========  ===============       =================================================
--   25-May-2021  Zane Gibson           Initial Creation
--   25-May-2021  Aaron Stevens         Added function FN_POST_AUTHENTICATE
--   27-May-2021  Dwain Wagner            Add:
--                                          *fn_add_subscriber - add subscriber to pbx
--   31-May-2021  Dwain Wagner            Add:
--                                          *fn_find_trunk - find trunk to complete pbx
--   03-Jun-2021  Dwain Wagner            Add:
--                                          *fn_add_tenant - add tenant to MultiTenant Manager
--   04-Jun-2021  Keenan Bernard        Added function FN_DELETE_SUBSCRIBER
--   04-Jun-2021  Aaron Stevens         Added function FN_UPDATE_SUBSCRIBER
--   08-Jun-2021  Aaron Stevens         Added function FN_POST_AUTHENTICATE_TENANT
--   08-Jun-2021  Keenan Bernard        Added function FN_GET_TENANTS
--   10-Jun-2021  Keenan Bernard        Updated function FN_GET_TENANTS
--   10-Jun-2021  Aaron Stevens         Updated function FN_GET_RESOURCE_PLANS_ID
--   14-Jun-2021  Aaron Stevens         Added function FN_UPDATE_TENANT
--   28-Jun-2021  Keenan Bernard        Updated function FN_GET_TENANTS - Numeric Validation
--   29-Jun-2021  Keenan Bernard        Updated function FN_GET_TENANTS - Plan Name
--   01-Jul-2021  Zane Gibson           Updated function FN_ADD_SUBSCRIBER:
--                                      i) Updated PBX Image value and added whitelisting element to allow CPBX provisioning from Middleware
--                                      ii) Add input validation for trunk 
--   01-Jul-2021  Keenan Bernard        Updated function FN_DELETE_SUBSCRIBER - Numeric Validation 
--   05-Jul-2021  Keenan Bernard        Updated function FN_DELETE_TENANT - Numeric Validation
--   09-Jul-2021  Dwain Wagner          Add:
--                                          1) FN_SSH_CONNECT - Allow system to connect to remotely via ssh and perform an action
--   14-Jul-2021  Aaron Stevens         Updated function FN_UPDATE_SUBSCRIBER- Numeric Validation 
--   14-Jul-2021  Aaron Stevens         Added function FN_UPDATE_TRUNK_U2000_MIDDB
--   14-Jul-2021  Keenan Bernard        Added function FN_DELETE_TRUNK_U2000
--   16-Jul-2021  Keenan Bernard        Update of Error Codes
--   19-Jul-2021  Dwain Wagner          Update of Error Codes and Password
--   19-Jul-2021  Keenan Bernard        Update function FN_GET_TENANTS - Status & DID output
--   26-Jul-2021  Keenan Bernard        Update function FN_GET_TENANTS - Status output
--   04-Aug-2021  Dwain Wagner          Add:
--                                          *fn_reconnect_subscriber - Start Tenant on the Multi Tenant System
--   09-Aug-2021  Aaron Stevens         Added function FN_SUSPEND_SUBSCRIBER
-- -------------------------------------------------------------------------------
    gv_codsystem VARCHAR2(20) := 'HOSTED'; 
--Complete PBX
    gv_http_url VARCHAR2(200) := 'pbx.btl.net/api';
    gv_key VARCHAR2(200) := 'btl_prov_eo9i7q3yzu8j6q0rkkcj9iatvk7y64rk4aus9mvm';
    gv_outgoing_host VARCHAR2(20) := 'ims.btl.net';
    gv_outgoing_fromdomain VARCHAR2(20) := 'ims.btl.net';
    gv_outbound_proxy VARCHAR2(20) := '172.26.3.227';
    gv_outgoing_insecure VARCHAR2(20) := 'port,invite';
    gv_outgoing_type VARCHAR2(1) := '1';   --Allow inbound calls
    gv_outgoing_port NUMBER := 5060;
--MultiTenant Manager
    gv_http_tenant_url VARCHAR2(200) := 'https://pbx.btl.net/api';
    gv_url VARCHAR2(200) := 'https://devtest.pbx.btl.net/api/authenticate';
    gv_plan_s VARCHAR2(50) := '334c21fe-b4a1-284f-d60e-a4838bae3eb4';
    gv_plan_m VARCHAR2(50) := '33331b55-6306-d7bb-ba5b-a7cb2aebd479';
    gv_plan_l VARCHAR2(50) := 'd4c7a3cb-2658-e2ca-8977-92b8c90abe12';
--U2000
    gv_get_u2000 VARCHAR2(50) := 'get_telnet_1.sh';
    gv_add_u2000 VARCHAR2(50) := 'add_telnet_1.sh';
    gv_update_u2000 VARCHAR2(50) := 'update_telnet_1.sh';
    gv_delete_u2000 VARCHAR2(50) := 'remove_telnet_1.sh';
    FUNCTION fn_post_authenticate (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_token        OUT             VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_add_trunk_cpbx (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vi_t_password   IN              VARCHAR2,
        vi_product      IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_find_trunk (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_product      VARCHAR2,
        vo_trunk_id     OUT             NUMBER,
        vo_t_username   OUT             VARCHAR2,
        vo_t_password   OUT             VARCHAR2,
        vo_result       OUT             NUMBER,
        vo_message      OUT             VARCHAR2
    ) RETURN NUMBER;

    FUNCTION fn_add_subscriber (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_plan         VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_get_tenant_id (
        vi_username             VARCHAR2,
        vi_password             VARCHAR2,
        vi_ip_info              VARCHAR2,
        vi_t_number             VARCHAR2,
        vo_tenants_id           OUT                     VARCHAR2,
        vo_tenant_resource_id   OUT                     VARCHAR2,
        vo_message              OUT                     VARCHAR2,
        vo_result               OUT                     NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_add_did (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_did_number   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_update_subscriber (
        vi_username         VARCHAR2,
        vi_password         VARCHAR2,
        vi_ip_info          VARCHAR2,
        vi_t_username       VARCHAR2,
        vi_t_new_username   VARCHAR2,
        vi_t_new_password   VARCHAR2,
        vi_product          IN                  VARCHAR2,
        vo_result           OUT                 NUMBER,
        vo_message          OUT                 VARCHAR2
    ) RETURN NUMBER;

    FUNCTION fn_post_authenticate_tenant (
        vi_username   VARCHAR2,
        vi_password   VARCHAR2,
        vi_ip_info    VARCHAR2,
        vo_t_token    OUT           VARCHAR2,
        vo_message    OUT           VARCHAR2,
        vo_result     OUT           NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_delete_subscriber (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vi_product      IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             INT
    ) RETURN NUMBER;

    FUNCTION fn_get_tenant (
        vi_username   VARCHAR2,
        vi_password   VARCHAR2,
        vi_ip_info    VARCHAR2,
        vi_t_number   VARCHAR2,
        vo_tenants    OUT           VARCHAR2,
        vo_message    OUT           VARCHAR2,
        vo_result     OUT           NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_get_resource_plan_id (
        vi_username           VARCHAR2,
        vi_password           VARCHAR2,
        vi_ip_info            VARCHAR2,
        vi_plan_name          VARCHAR2,
        vo_resource_plan_id   OUT                   VARCHAR2,
        vo_message            OUT                   VARCHAR2,
        vo_result             OUT                   NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_get_resource_plan_nm (
        vi_username           VARCHAR2,
        vi_password           VARCHAR2,
        vi_ip_info            VARCHAR2,
        vi_resource_plan_id   VARCHAR2,
        vo_plan_nm            OUT                   VARCHAR2,
        vo_message            OUT                   VARCHAR2,
        vo_result             OUT                   NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_update_tenant (
        vi_username         VARCHAR2,
        vi_password         VARCHAR2,
        vi_ip_info          VARCHAR2,
        vi_t_username       VARCHAR2,
        vi_t_new_username   VARCHAR2,
        vi_plan_name        VARCHAR2,
        vo_message          OUT                 VARCHAR2,
        vo_result           OUT                 NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_delete_tenant (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_delete_did (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vi_did_number   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_update_trunk_u2000_middb (
        vi_username         VARCHAR2,
        vi_password         VARCHAR2,
        vi_ip_info          VARCHAR2,
        vi_t_username       VARCHAR2,
        vi_t_new_username   VARCHAR2,
        vo_result           OUT                 NUMBER,
        vo_message          OUT                 VARCHAR2
    ) RETURN NUMBER;

    FUNCTION fn_get_trunk_u2000 (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_add_trunk_u2000 (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_add_trunk_helper_cpbx (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vi_t_password   IN              VARCHAR2,
        vi_product      IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_reconnect_subscriber (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

    FUNCTION fn_ssh_connect (
        inputs VARCHAR2
    ) RETURN VARCHAR2;

    FUNCTION fn_delete_trunk_u2000 (
        vi_username     IN              VARCHAR2,
        vi_password     IN              VARCHAR2,
        vi_ip_info      IN              VARCHAR2,
        vi_t_username   IN              VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             INT
    ) RETURN NUMBER;

    FUNCTION fn_suspend_subscriber (
        vi_username     VARCHAR2,
        vi_password     VARCHAR2,
        vi_ip_info      VARCHAR2,
        vi_t_username   VARCHAR2,
        vo_message      OUT             VARCHAR2,
        vo_result       OUT             NUMBER
    ) RETURN NUMBER;

END pck_pbx;
