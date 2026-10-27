from typing import List, Dict, Any

# 5 High-Fidelity Synthetic Indian Legal Judgments with Manually Labeled Ground Truth
SYNTHETIC_JUDGMENTS: List[Dict[str, Any]] = [
    {
        "id": "SYNTH_JUDGMENT_01",
        "title": "Criminal Appeal (POCSO Act & S.376 IPC) - State of NCT of Delhi v. Ramesh Kumar",
        "case_number": "CRL.A. 412/2021",
        "court": "HIGH COURT OF DELHI AT NEW DELHI",
        "text": """IN THE HIGH COURT OF DELHI AT NEW DELHI
CRIMINAL APPEAL NO. 412 OF 2021
(Arising out of FIR No. 128/2019 registered at P.S. Malviya Nagar)

IN THE MATTER OF:
Ramesh Kumar, aged 34 years,
S/o Shri Harish Kumar,
R/o House No. 45-B, Gali No. 3, Begumpur, New Delhi - 110017
Mobile: +91 9811234567, Aadhaar: 2341 5678 9012
... Appellant/Convict

VERSUS

State (NCT of Delhi)
Through Public Prosecutor
... Respondent

CORAM:
HON'BLE MR. JUSTICE SURESH KUMAR KAIT
HON'BLE MS. JUSTICE NEENA BANSAL KRISHNA

JUDGMENT
1. The present criminal appeal challenges judgment of conviction dated 12.03.2021 under Section 6 of the POCSO Act, 2012 and Section 376(2)(n) of the Indian Penal Code.
2. The prosecution case stems from complaint lodged by complainant Smt. Sharda Devi, mother of the minor victim Priya Sharma, aged 13 years, born on 14-06-2006.
3. According to PW-1 Priya Sharma (victim), the appellant Ramesh Kumar resided in the adjacent tenement and lured her on 10.05.2019. Medical examination was conducted by Dr. Anita Roy at Safdarjung Hospital.
4. PW-2 Inspector Virender Singh, Investigating Officer, recovered PAN Card ABCDE1234F belonging to the accused and recorded statements of witness Rajesh Verma.
5. In accordance with Section 33(7) of the POCSO Act and Section 228A IPC, the registry is directed to anonymize identity of the child.""",
        "ground_truth_entities": [
            {"text": "Ramesh Kumar", "category": "PERSON_NAME", "role": "APPELLANT"},
            {"text": "34", "category": "AGE", "role": "APPELLANT"},
            {"text": "Harish Kumar", "category": "PERSON_NAME", "role": "FAMILY_MEMBER"},
            {"text": "House No. 45-B, Gali No. 3, Begumpur, New Delhi - 110017", "category": "RESIDENTIAL_ADDRESS", "role": "GENERAL_INDIVIDUAL"},
            {"+91 9811234567": "PHONE", "text": "+91 9811234567", "category": "PHONE", "role": "GENERAL_INDIVIDUAL"},
            {"text": "2341 5678 9012", "category": "AADHAAR", "role": "GENERAL_INDIVIDUAL"},
            {"text": "Sharda Devi", "category": "PERSON_NAME", "role": "FAMILY_MEMBER"},
            {"text": "Priya Sharma", "category": "PERSON_NAME", "role": "VICTIM"},
            {"text": "13", "category": "AGE", "role": "VICTIM"},
            {"text": "14-06-2006", "category": "DATE_OF_BIRTH", "role": "VICTIM"},
            {"text": "Dr. Anita Roy", "category": "PERSON_NAME", "role": "GENERAL_INDIVIDUAL"},
            {"text": "Virender Singh", "category": "PERSON_NAME", "role": "POLICE_OFFICER"},
            {"text": "ABCDE1234F", "category": "PAN", "role": "GENERAL_INDIVIDUAL"},
            {"text": "Rajesh Verma", "category": "PERSON_NAME", "role": "WITNESS"},
        ]
    },
    {
        "id": "SYNTH_JUDGMENT_02",
        "title": "Matrimonial Dispute (Hindu Marriage Act) - Sunita Gupta v. Alok Gupta",
        "case_number": "MAT.APP.(F.C.) 89/2022",
        "court": "HIGH COURT OF JUDICATURE AT BOMBAY",
        "text": """IN THE HIGH COURT OF JUDICATURE AT BOMBAY
FAMILY COURT APPEAL NO. 89 OF 2022

Sunita Gupta, aged about 31 years,
W/o Shri Alok Gupta, D/o Late Jagdish Prasad,
R/o Flat 402, Sea Crest Towers, Worli, Mumbai - 400018
Email: sunita.gupta@example.in, Phone: 9820198201
... Appellant

VERSUS

Alok Gupta, aged 35 years,
S/o Shri Murari Lal Gupta,
R/o Bungalow No. 12, Baner Road, Pune - 411045
PAN: BCDFG5678K, Bank A/c No. 50100234567891 with HDFC Bank
... Respondent

BEFORE: HON'BLE MR. JUSTICE NITIN SAMBRE
1. This appeal arises out of dissolution of marriage under Section 13(1)(ia) of the Hindu Marriage Act, 1955.
2. The parties have one minor son, Master Aarav Gupta, born on 22/11/2015, presently studying in Mumbai.
3. The respondent deposited maintenance via UPI ID alokgupta@okaxis in compliance with family court directions.""",
        "ground_truth_entities": [
            {"text": "Sunita Gupta", "category": "PERSON_NAME", "role": "PETITIONER"},
            {"text": "31", "category": "AGE", "role": "PETITIONER"},
            {"text": "Alok Gupta", "category": "PERSON_NAME", "role": "RESPONDENT"},
            {"text": "Jagdish Prasad", "category": "PERSON_NAME", "role": "FAMILY_MEMBER"},
            {"text": "Flat 402, Sea Crest Towers, Worli, Mumbai - 400018", "category": "RESIDENTIAL_ADDRESS", "role": "GENERAL_INDIVIDUAL"},
            {"text": "sunita.gupta@example.in", "category": "EMAIL", "role": "GENERAL_INDIVIDUAL"},
            {"text": "9820198201", "category": "PHONE", "role": "GENERAL_INDIVIDUAL"},
            {"text": "35", "category": "AGE", "role": "RESPONDENT"},
            {"text": "Murari Lal Gupta", "category": "PERSON_NAME", "role": "FAMILY_MEMBER"},
            {"text": "Bungalow No. 12, Baner Road, Pune - 411045", "category": "RESIDENTIAL_ADDRESS", "role": "GENERAL_INDIVIDUAL"},
            {"text": "BCDFG5678K", "category": "PAN", "role": "GENERAL_INDIVIDUAL"},
            {"text": "50100234567891", "category": "BANK_ACCOUNT", "role": "GENERAL_INDIVIDUAL"},
            {"text": "Aarav Gupta", "category": "PERSON_NAME", "role": "MINOR"},
            {"text": "22/11/2015", "category": "DATE_OF_BIRTH", "role": "MINOR"},
            {"text": "alokgupta@okaxis", "category": "UPI_ID", "role": "GENERAL_INDIVIDUAL"},
        ]
    },
    {
        "id": "SYNTH_JUDGMENT_03",
        "title": "Cheque Dishonour (S.138 NI Act) - Zenith Infotech v. Vikram Singhania",
        "case_number": "CRL.REV.P. 512/2020",
        "court": "HIGH COURT OF KARNATAKA AT BENGALURU",
        "text": """IN THE HIGH COURT OF KARNATAKA AT BENGALURU
CRIMINAL REVISION PETITION NO. 512 OF 2020

Zenith Infotech Private Limited,
Represented by its Authorised Representative Shri Deepak Mehta
... Petitioner

VERSUS

Vikram Singhania,
Proprietor of M/s Singhania Traders,
R/o 14th Cross, Malleshwaram, Bengaluru - 560003
PAN: ASDFG9988Z, IFSC: SBIN0004051, Account: 30894512903
Mobile: 9448123456
... Respondent

CORAM: HON'BLE MR. JUSTICE H.P. SANDESH
1. The petitioner filed complaint under Section 138 of Negotiable Instruments Act, 1881 regarding dishonour of cheque for Rs. 15,00,000/-.
2. The trial court convicted the respondent citing Dalmia Cement (Bharat) Ltd. v. Galaxy Traders (AIR 2001 SC 676).""",
        "ground_truth_entities": [
            {"text": "Deepak Mehta", "category": "PERSON_NAME", "role": "PETITIONER"},
            {"text": "Vikram Singhania", "category": "PERSON_NAME", "role": "RESPONDENT"},
            {"text": "14th Cross, Malleshwaram, Bengaluru - 560003", "category": "RESIDENTIAL_ADDRESS", "role": "GENERAL_INDIVIDUAL"},
            {"text": "ASDFG9988Z", "category": "PAN", "role": "GENERAL_INDIVIDUAL"},
            {"text": "SBIN0004051", "category": "IFSC", "role": "GENERAL_INDIVIDUAL"},
            {"text": "30894512903", "category": "BANK_ACCOUNT", "role": "GENERAL_INDIVIDUAL"},
            {"text": "9448123456", "category": "PHONE", "role": "GENERAL_INDIVIDUAL"},
        ]
    },
    {
        "id": "SYNTH_JUDGMENT_04",
        "title": "Anticipatory Bail Application (S.438 CrPC) - Sandeep Yadav v. State of Haryana",
        "case_number": "CRM-M-23456-2022",
        "court": "HIGH COURT OF PUNJAB AND HARYANA AT CHANDIGARH",
        "text": """IN THE HIGH COURT OF PUNJAB AND HARYANA AT CHANDIGARH
CRM-M NO. 23456 OF 2022

Sandeep Yadav, aged 29 years,
S/o Shri Mahender Yadav,
R/o Village Kasan, Tehsil Manesar, District Gurugram, Haryana
Aadhaar: 7654 3210 9876
... Petitioner

VERSUS

State of Haryana
Through Standing Counsel
... Respondent

BEFORE: HON'BLE MR. JUSTICE ARVIND SINGH SANGWAN
Advocates: Mr. Kapil Sibal, Senior Advocate with Mr. Rohit Sharma for Petitioner.
Mr. Naveen Sheoran, DAG Haryana.

ORDER
1. This is a petition under Section 438 Cr.P.C. for grant of anticipatory bail in FIR No. 89/2022 registered under Sections 420, 406 IPC at Police Station Kherki Daula.
2. Learned counsel submits that the petitioner has been falsely implicated by complainant Manoj Tiwari over property transactions.""",
        "ground_truth_entities": [
            {"text": "Sandeep Yadav", "category": "PERSON_NAME", "role": "PETITIONER"},
            {"text": "29", "category": "AGE", "role": "PETITIONER"},
            {"text": "Mahender Yadav", "category": "PERSON_NAME", "role": "FAMILY_MEMBER"},
            {"text": "Village Kasan, Tehsil Manesar, District Gurugram, Haryana", "category": "RESIDENTIAL_ADDRESS", "role": "GENERAL_INDIVIDUAL"},
            {"text": "7654 3210 9876", "category": "AADHAAR", "role": "GENERAL_INDIVIDUAL"},
            {"text": "Kapil Sibal", "category": "PERSON_NAME", "role": "LAWYER"},
            {"text": "Rohit Sharma", "category": "PERSON_NAME", "role": "LAWYER"},
            {"text": "Naveen Sheoran", "category": "PERSON_NAME", "role": "LAWYER"},
            {"text": "Manoj Tiwari", "category": "PERSON_NAME", "role": "WITNESS"},
        ]
    },
    {
        "id": "SYNTH_JUDGMENT_05",
        "title": "Motor Accident Claim (MACT) - Rekha Devi & Ors. v. National Insurance Co.",
        "case_number": "MAC.APP. 340/2019",
        "court": "HIGH COURT OF DELHI AT NEW DELHI",
        "text": """IN THE HIGH COURT OF DELHI AT NEW DELHI
MAC. APP. NO. 340 OF 2019

1. Smt. Rekha Devi, aged 42 years, W/o Late Subhash Chand
2. Master Kunal, aged 11 years, S/o Late Subhash Chand
R/o H.No. 88, Village Ghitorni, Vasant Kunj, New Delhi - 110070
... Appellants / Claimants

VERSUS

1. National Insurance Co. Ltd.
2. Pradeep Verma (Driver), R/o Sector 15, Faridabad
Vehicle Involved: Truck bearing No. HR-38-S-4590
... Respondents

CORAM: HON'BLE MR. JUSTICE J.R. MIDHA
1. Claimants appeal enhancement of compensation awarded under Section 166 of Motor Vehicles Act, 1988 for death of Subhash Chand in accident on 14.03.2018.
2. Compensation of Rs. 24,50,000/- ordered deposited in Claimants' Savings Account with State Bank of India.""",
        "ground_truth_entities": [
            {"text": "Rekha Devi", "category": "PERSON_NAME", "role": "PETITIONER"},
            {"text": "42", "category": "AGE", "role": "PETITIONER"},
            {"text": "Subhash Chand", "category": "PERSON_NAME", "role": "VICTIM"},
            {"text": "Kunal", "category": "PERSON_NAME", "role": "MINOR"},
            {"text": "11", "category": "AGE", "role": "MINOR"},
            {"text": "H.No. 88, Village Ghitorni, Vasant Kunj, New Delhi - 110070", "category": "RESIDENTIAL_ADDRESS", "role": "GENERAL_INDIVIDUAL"},
            {"text": "Pradeep Verma", "category": "PERSON_NAME", "role": "RESPONDENT"},
            {"text": "Sector 15, Faridabad", "category": "RESIDENTIAL_ADDRESS", "role": "GENERAL_INDIVIDUAL"},
            {"text": "HR-38-S-4590", "category": "VEHICLE_NUMBER", "role": "GENERAL_INDIVIDUAL"},
        ]
    }
]
