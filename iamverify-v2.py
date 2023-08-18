import boto3
import json

# Conexão à AWS
client = boto3.client('accessanalyzer')

# Obter os resultados da avaliação
response = client.list_findings(analyzerArn='arn:aws:access-analyzer:us-west-2:123456789012:analyzer/my-iam-assessment')

# Converter para o formato SARIF
sarif_results = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "AWS IAM Assessment",
                    "informationUri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"
                }
            },
            "results": []
        }
    ]
}

for finding in response['findings']:
    sarif_results['runs'][0]['results'].append({
        "ruleId": finding['findingId'],
        "level": "error",
        "message": {
            "text": finding['findingDetails']
        }
    })

# Salvar o relatório SARIF em um arquivo
with open("aws_iam_assessment.sarif", "w") as f:
    json.dump(sarif_results, f, indent=2)
