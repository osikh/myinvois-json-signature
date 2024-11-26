import pytz
from datetime import timedelta, datetime

def main():
    # Set version code
    version_code = "1.1"

    # LHDN required UTC timestamp
    # Using pytz to set timezone to UTC
    utc_timezone = pytz.utc

    # Format the signingDatetime as required
    # this datetime will be used as SIGNING TIMESTAMP
    utcDatetime = datetime.now(utc_timezone).strftime('%Y-%m-%dT%H:%M:%SZ')

    # fix it for easy debugging
    utcDatetime = "2024-11-25T07:52:32Z"

    # Separate the date and time parts from the invoiceDateTime
    # Subtracting 10 minutes from the current time for invoice date and time
    invoice_datetime = datetime.now(utc_timezone) - timedelta(minutes=10)
    invoice_date = invoice_datetime.strftime('%Y-%m-%d')
    invoice_time = invoice_datetime.strftime('%H:%M:%SZ')

    # Supplier information
    supplier_tin = "C20839371040"
    supplier_id_value = "200601000306"
    supplier_id_type = "BRN"
    supplier_email = 'einvoice_smjteratai@smjremit.com'
    supplier_legal_name = 'SMJ TERATAI SDN. BHD.'
    supplier_phone = '0123456789'

    # Customer information
    customer_tin = "IG21062484010"
    customer_id_value = "850812136079"
    customer_id_type = "NRIC"

    # Certificate file and PIN (for later use, e.g., for signing)
    certificate_file = 'cert/cert_smj.p12'
    certificate_pin = 'Kb0!k#Qv'

    # Load the Certificate
    # certificate, private_key, add_certificates = load_certificate(certificate_file, certificate_pin)
    # certInfo = get_cert_info(certificate)

    minifiedJson = '{"_D":"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2","_A":"urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2","_B":"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2","Invoice":[{"ID":[{"_":"705725225958"}],"IssueDate":[{"_":"'+invoice_date+'"}],"IssueTime":[{"_":"'+invoice_time+'"}],"InvoiceTypeCode":[{"_":"01","listVersionID":"'+version_code+'"}],"DocumentCurrencyCode":[{"_":"MYR"}],"InvoicePeriod":[{"StartDate":[{"_":""}],"EndDate":[{"_":""}],"Description":[{"_":""}]}],"BillingReference":[{"AdditionalDocumentReference":[{"ID":[{"_":"1234"}]}]}],"AdditionalDocumentReference":[{"ID":[{"_":"762673792005"}]}],"AccountingSupplierParty":[{"AdditionalAccountID":[{"_":"","schemeAgencyName":"CertEx"}],"Party":[{"IndustryClassificationCode":[{"_":"61902","name":"Provision of telecommunications services over existing telecom connection"}],"PartyIdentification":[{"ID":[{"_":"'+supplier_tin+'","schemeID":"TIN"}]},{"ID":[{"_":"'+supplier_id_value+'","schemeID":"'+supplier_id_type+'"}]},{"ID":[{"_":"02332234234343","schemeID":"SST"}]},{"ID":[{"_":"03434234342343432","schemeID":"TTX"}]}],"PostalAddress":[{"CityName":[{"_":"ASAJAYA"}],"PostalZone":[{"_":"94600"}],"CountrySubentityCode":[{"_":"01"}],"AddressLine":[{"Line":[{"_":"Line 1"}]},{"Line":[{"_":"Line 2"}]},{"Line":[{"_":"Line 3"}]}],"Country":[{"IdentificationCode":[{"_":"MYS","listID":"3166-1","listAgencyID":"ISO"}]}]}],"PartyLegalEntity":[{"RegistrationName":[{"_":"'+supplier_legal_name+'"}]}],"Contact":[{"Telephone":[{"_":"'+supplier_phone+'"}],"ElectronicMail":[{"_":"'+supplier_email+'"}]}]}]}],"AccountingCustomerParty":[{"Party":[{"PartyIdentification":[{"ID":[{"_":"'+customer_tin+'","schemeID":"TIN"}]},{"ID":[{"_":"'+customer_id_value+'","schemeID":"'+customer_id_type+'"}]}],"PostalAddress":[{"CityName":[{"_":"SEMUA NEGERI"}],"PostalZone":[{"_":"81500"}],"CountrySubentityCode":[{"_":"00"}],"AddressLine":[{"Line":[{"_":"buyerAddressLine1"}]},{"Line":[{"_":"buyerAddressLine2"}]},{"Line":[{"_":""}]}],"Country":[{"IdentificationCode":[{"_":"MYS","listID":"3166-1","listAgencyID":"ISO"}]}]}],"PartyLegalEntity":[{"RegistrationName":[{"_":"BuyerName"}]}],"Contact":[{"Telephone":[{"_":"123456789012"}],"ElectronicMail":[{"_":"Buyer@gmail.com"}]}]}]}],"Delivery":[{"DeliveryParty":[{"PartyLegalEntity":[{"RegistrationName":[{"_":""}]}],"PostalAddress":[{"CityName":[{"_":""}],"PostalZone":[{"_":""}],"CountrySubentityCode":[{"_":""}],"AddressLine":[{"Line":[{"_":""}]},{"Line":[{"_":""}]},{"Line":[{"_":""}]}],"Country":[{"IdentificationCode":[{"_":"","listID":"","listAgencyID":""}]}]}],"PartyIdentification":[{"ID":[{"_":"","schemeID":""}]}]}],"Shipment":[{"ID":[{"_":""}],"FreightAllowanceCharge":[{"ChargeIndicator":[{"_":true}],"AllowanceChargeReason":[{"_":""}],"Amount":[{"_":0,"currencyID":"MYR"}]}]}]}],"PaymentMeans":[{"PaymentMeansCode":[{"_":""}],"PayeeFinancialAccount":[{"ID":[{"_":""}]}]}],"PaymentTerms":[{"Note":[{"_":""}]}],"PrepaidPayment":[{"ID":[{"_":""}],"PaidAmount":[{"_":0,"currencyID":"MYR"}],"PaidDate":[{"_":""}],"PaidTime":[{"_":""}]}],"AllowanceCharge":[{"ChargeIndicator":[{"_":true}],"AllowanceChargeReason":[{"_":""}],"Amount":[{"_":0,"currencyID":"MYR"}]},{"ChargeIndicator":[{"_":false}],"AllowanceChargeReason":[{"_":""}],"Amount":[{"_":0,"currencyID":"MYR"}]}],"TaxTotal":[{"TaxAmount":[{"_":15680,"currencyID":"MYR"}],"TaxSubtotal":[{"TaxableAmount":[{"_":784000,"currencyID":"MYR"}],"TaxAmount":[{"_":15680,"currencyID":"MYR"}],"TaxCategory":[{"ID":[{"_":"02"}],"TaxScheme":[{"ID":[{"_":"OTH","schemeAgencyID":"6","schemeID":"UN/ECE 5153"}]}]}]}]}],"LegalMonetaryTotal":[{"LineExtensionAmount":[{"_":784000,"currencyID":"MYR"}],"TaxExclusiveAmount":[{"_":784000,"currencyID":"MYR"}],"TaxInclusiveAmount":[{"_":799680,"currencyID":"MYR"}],"AllowanceTotalAmount":[{"_":0,"currencyID":"MYR"}],"ChargeTotalAmount":[{"_":0,"currencyID":"MYR"}],"PayableAmount":[{"_":799680,"currencyID":"MYR"}],"PayableRoundingAmount":[{"_":0,"currencyID":"MYR"}]}],"InvoiceLine":[{"AllowanceCharge":[{"Amount":[{"_":16000,"currencyID":"MYR"}],"ChargeIndicator":[{"_":false}],"MultiplierFactorNumeric":[{"_":2}],"AllowanceChargeReason":[{"_":"Reason"}]}],"ID":[{"_":"1"}],"InvoicedQuantity":[{"_":80,"unitCode":"KAT"}],"Item":[{"CommodityClassification":[{"ItemClassificationCode":[{"_":"002","listID":"CLASS"}]}],"Description":[{"_":"Product"}],"OriginCountry":[{"IdentificationCode":[{"_":""}]}]}],"ItemPriceExtension":[{"Amount":[{"_":800000,"currencyID":"MYR"}]}],"LineExtensionAmount":[{"_":784000,"currencyID":"MYR"}],"Price":[{"PriceAmount":[{"_":10000,"currencyID":"MYR"}]}],"TaxTotal":[{"TaxAmount":[{"_":15680,"currencyID":"MYR"}],"TaxSubtotal":[{"TaxableAmount":[{"_":784000,"currencyID":"MYR"}],"TaxAmount":[{"_":15680,"currencyID":"MYR"}],"Percent":[{"_":2}],"TaxCategory":[{"ID":[{"_":"02"}],"TaxScheme":[{"ID":[{"_":"OTH","schemeAgencyID":"6","schemeID":"UN/ECE 5153"}]}]}]}]}]},{"AllowanceCharge":[{"Amount":[{"_":16000,"currencyID":"MYR"}],"ChargeIndicator":[{"_":false}],"MultiplierFactorNumeric":[{"_":2}],"AllowanceChargeReason":[{"_":"Reason"}]}],"ID":[{"_":"2"}],"InvoicedQuantity":[{"_":80,"unitCode":"KAT"}],"Item":[{"CommodityClassification":[{"ItemClassificationCode":[{"_":"003","listID":"CLASS"}]}],"Description":[{"_":"Product"}],"OriginCountry":[{"IdentificationCode":[{"_":""}]}]}],"ItemPriceExtension":[{"Amount":[{"_":800000,"currencyID":"MYR"}]}],"LineExtensionAmount":[{"_":784000,"currencyID":"MYR"}],"Price":[{"PriceAmount":[{"_":10000,"currencyID":"MYR"}]}],"TaxTotal":[{"TaxAmount":[{"_":15680,"currencyID":"MYR"}],"TaxSubtotal":[{"TaxableAmount":[{"_":784000,"currencyID":"MYR"}],"TaxAmount":[{"_":15680,"currencyID":"MYR"}],"Percent":[{"_":2}],"TaxCategory":[{"ID":[{"_":"02"}],"TaxScheme":[{"ID":[{"_":"OTH","schemeAgencyID":"6","schemeID":"UN/ECE 5153"}]}]}]}]}]}],"TaxExchangeRate":[{"SourceCurrencyCode":[{"_":"MYR"}],"TargetCurrencyCode":[{"_":"MYR"}],"CalculationRate":[{"_":0}]}]}]}'

    with open("json_files/input.json", 'w', encoding='utf-8') as file:
        file.write(minifiedJson)

if __name__ == "__main__":
    main()